package backends

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	read      = "read"
	write     = "write"
	readwrite = "readwrite"
	subscribe = "subscribe"
	deny      = "deny"
)

var permissions = map[string]byte{
	read:      MOSQ_ACL_READ,
	write:     MOSQ_ACL_WRITE,
	readwrite: MOSQ_ACL_READWRITE,
	subscribe: MOSQ_ACL_SUBSCRIBE,
	deny:      MOSQ_ACL_DENY,
}

//FileUer keeps a user password and acl records.
type FileUser struct {
	Password   string
	AclRecords []AclRecord
}

//AclRecord holds a topic and access privileges.
type AclRecord struct {
	Topic string
	Acc   byte //None 0x00, Read 0x01, Write 0x02, ReadWrite: Read | Write : 0x03, Subscribe 0x04, Deny 0x11
}

//FileBE holds paths to files, list of file users and general (no user or pattern) acl records.
type Files struct {
	sync.Mutex
	PasswordPath string
	AclPath      string
	CheckAcls    bool
	Users        map[string]*FileUser //Users keeps a registry of username/FileUser pairs, holding a user's password and Acl records.
	AclRecords   []AclRecord
	filesOnly    bool
	hasher       hashing.HashComparer
	signals      chan os.Signal
}

//NewFiles initializes a files backend.
func NewFiles(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (*Files, error) {

	log.SetLevel(logLevel)

	var files = &Files{
		PasswordPath: "",
		AclPath:      "",
		CheckAcls:    false,
		Users:        make(map[string]*FileUser),
		AclRecords:   make([]AclRecord, 0),
		filesOnly:    true,
		hasher:       hasher,
		signals:      make(chan os.Signal, 1),
	}

	if len(strings.Split(strings.Replace(authOpts["backends"], " ", "", -1), ",")) > 1 {
		files.filesOnly = false
	}

	if passwordPath, ok := authOpts["password_path"]; ok {
		files.PasswordPath = passwordPath
	} else {
		return nil, errors.New("Files backend error: no password path given")
	}

	if aclPath, ok := authOpts["acl_path"]; ok {
		files.AclPath = aclPath
		files.CheckAcls = true
	} else {
		files.CheckAcls = false
		log.Info("Acls won't be checked")
	}

	err := files.loadFiles()
	if err != nil {
		return nil, err
	}

	go files.watchSignals()

	return files, nil
}

func (o *Files) watchSignals() {
	signal.Notify(o.signals, syscall.SIGHUP)

	for {
		select {
		case sig := <-o.signals:
			if sig == syscall.SIGHUP {
				log.Debugln("Got SIGHUP, reloading files.")
				o.loadFiles()
			}
		}
	}
}

func (o *Files) loadFiles() error {
	o.Lock()
	defer o.Unlock()

	count, err := o.readPasswords()
	if err != nil {
		return errors.Errorf("read passwords: %s", err)
	}

	log.Debugf("got %d users from passwords file", count)

	//Only read acls if path was given.
	if o.CheckAcls {
		count, err := o.readAcls()
		if err != nil {
			return errors.Errorf("read acls: %s", err)
		}

		log.Debugf("got %d lines from acl file", count)
	}

	return nil
}

//ReadPasswords read file and populates FileUsers. Return amount of users seen and possile error.
func (o *Files) readPasswords() (int, error) {

	usersCount := 0

	file, err := os.Open(o.PasswordPath)
	if err != nil {
		return usersCount, fmt.Errorf("Files backend error: couldn't open passwords file: %s", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	index := 0
	//Read line by line
	for scanner.Scan() {
		index++

		//Check comment or empty line to skip them.
		if checkCommentOrEmpty(scanner.Text()) {
			continue
		}

		lineArr := strings.Split(scanner.Text(), ":")
		if len(lineArr) != 2 {
			log.Errorf("Read passwords error: line %d is not well formatted", index)
			continue
		}
		//Create user if it doesn't exist and save password; override password if user existed.
		var fileUser *FileUser
		var ok bool
		fileUser, ok = o.Users[lineArr[0]]
		if ok {
			fileUser.Password = lineArr[1]
		} else {
			usersCount++
			fileUser = &FileUser{
				Password:   lineArr[1],
				AclRecords: make([]AclRecord, 0),
			}
			o.Users[lineArr[0]] = fileUser
		}
	}

	return usersCount, nil

}

// ReadAcls reads the Acl file and associates them to existing users. It omits any non existing users.
func (o *Files) readAcls() (int, error) {
	linesCount := 0
	currentUser := ""
	userExists := false

	file, err := os.Open(o.AclPath)
	if err != nil {
		return linesCount, errors.Errorf("Files backend error: couldn't open acl file: %s", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	index := 0

	for scanner.Scan() {
		index++

		if checkCommentOrEmpty(scanner.Text()) {
			continue
		}

		line := strings.TrimSpace(scanner.Text())

		lineArr := strings.Fields(line)
		prefix := lineArr[0]

		if prefix == "user" {
			// Since there may be more than one consecutive space in the username, we have to remove the prefix and trim to get the username.
			username, err := removeAndTrim(prefix, line, index)
			if err != nil {
				return 0, err
			}

			_, ok := o.Users[username]

			if !ok {
				log.Warnf("user %s doesn't exist, skipping acls", username)
				// Flag username to skip topics later.
				userExists = false
				continue
			}

			userExists = true
			currentUser = username
		} else if prefix == "topic" || prefix == "pattern" {
			var aclRecord = AclRecord{
				Topic: "",
				Acc:   MOSQ_ACL_NONE,
			}

			/*	If len is 2, then we assume ReadWrite privileges.

				Notice that Mosquitto docs prevent whitespaces in the topic when there's no explicit access given:
					"The access type is controlled using "read", "write", "readwrite" or "deny". This parameter is optional (unless <topic> includes a space character)"
					https://mosquitto.org/man/mosquitto-conf-5.html
				When access is given, then the topic may contain whitespaces.

				Nevertheless, there may be white spaces between topic/pattern and the permission or the topic itself.
				Fields captures the case in which there's only topic/pattern and the given topic because it trims extra spaces between them.
			*/
			if len(lineArr) == 2 {
				aclRecord.Topic = lineArr[1]
				aclRecord.Acc = MOSQ_ACL_READWRITE
			} else {
				// There may be more than one space between topic/pattern and the permission, as well as between the latter and the topic itself.
				// Hence, we remove the prefix, trim the line and split on white space to get the permission.
				line, err = removeAndTrim(prefix, line, index)
				if err != nil {
					return 0, err
				}

				lineArr = strings.Split(line, " ")
				permission := lineArr[0]

				// Again, there may be more than one space between the permission and the topic, so we'll trim what's left after removing it and that'll be the topic.
				topic, err := removeAndTrim(permission, line, index)
				if err != nil {
					return 0, err
				}

				switch permission {
				case read, write, readwrite, subscribe, deny:
					aclRecord.Acc = permissions[permission]
				default:
					return 0, errors.Errorf("Files backend error: wrong acl format at line %d", index)
				}

				aclRecord.Topic = topic
			}

			if prefix == "topic" {
				if currentUser != "" {
					// Skip topic when user was not found.
					if !userExists {
						continue
					}

					fUser, ok := o.Users[currentUser]
					if !ok {
						return 0, errors.Errorf("Files backend error: user does not exist for acl at line %d", index)
					}
					fUser.AclRecords = append(fUser.AclRecords, aclRecord)
				} else {
					o.AclRecords = append(o.AclRecords, aclRecord)
				}
			} else {
				o.AclRecords = append(o.AclRecords, aclRecord)
			}

			linesCount++

		} else {
			return 0, errors.Errorf("Files backend error: wrong acl format at line %d", index)
		}
	}

	return linesCount, nil
}

func removeAndTrim(prefix, line string, index int) (string, error) {
	if len(line)-len(prefix) < 1 {
		return "", errors.Errorf("Files backend error: wrong acl format at line %d", index)
	}
	newLine := strings.TrimSpace(line[len(prefix):])

	return newLine, nil
}

func checkCommentOrEmpty(line string) bool {
	if len(strings.Replace(line, " ", "", -1)) == 0 || line[0:1] == "#" {
		return true
	}
	return false
}

//GetUser checks that user exists and password is correct.
func (o *Files) GetUser(username, password, clientid string) (bool, error) {

	fileUser, ok := o.Users[username]
	if !ok {
		return false, nil
	}

	if o.hasher.Compare(password, fileUser.Password) {
		return true, nil
	}

	log.Warnf("wrong password for user %s", username)

	return false, nil

}

//GetSuperuser returns false for files backend.
func (o *Files) GetSuperuser(username string) (bool, error) {
	return false, nil
}

//CheckAcl checks that the topic may be read/written by the given user/clientid.
func (o *Files) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	//If there are no acls and Files is the only backend, all access is allowed.
	//If there are other backends, then we can't blindly grant access.
	if !o.CheckAcls {
		return o.filesOnly, nil
	}

	fileUser, ok := o.Users[username]

	// Check if the topic was explicitly denied and refuse to authorize if so.
	if ok {
		for _, aclRecord := range fileUser.AclRecords {
			match := TopicsMatch(aclRecord.Topic, topic)

			if match {
				if aclRecord.Acc == MOSQ_ACL_DENY {
					return false, nil
				}
			}
		}
	}

	for _, aclRecord := range o.AclRecords {
		aclTopic := strings.Replace(aclRecord.Topic, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)

		match := TopicsMatch(aclTopic, topic)

		if match {
			if aclRecord.Acc == MOSQ_ACL_DENY {
				return false, nil
			}
		}
	}

	// No denials, check against user's acls and common ones. If not authorized, check against pattern acls.
	if ok {
		for _, aclRecord := range fileUser.AclRecords {
			match := TopicsMatch(aclRecord.Topic, topic)

			if match {
				if acc == int32(aclRecord.Acc) || int32(aclRecord.Acc) == MOSQ_ACL_READWRITE || (acc == MOSQ_ACL_SUBSCRIBE && topic != "#" && (int32(aclRecord.Acc) == MOSQ_ACL_READ || int32(aclRecord.Acc) == MOSQ_ACL_SUBSCRIBE)) {
					return true, nil
				}
			}
		}
	}
	for _, aclRecord := range o.AclRecords {
		//Replace all occurrences of %c for clientid and %u for username
		aclTopic := strings.Replace(aclRecord.Topic, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)

		match := TopicsMatch(aclTopic, topic)

		if match {
			if acc == int32(aclRecord.Acc) || int32(aclRecord.Acc) == MOSQ_ACL_READWRITE || (acc == MOSQ_ACL_SUBSCRIBE && topic != "#" && (int32(aclRecord.Acc) == MOSQ_ACL_READ || int32(aclRecord.Acc) == MOSQ_ACL_SUBSCRIBE)) {
				return true, nil
			}
		}
	}

	return false, nil

}

//GetName returns the backend's name
func (o *Files) GetName() string {
	return "Files"
}

//Halt does nothing for files as there's no cleanup needed.
func (o *Files) Halt() {
	//Do nothing
}
