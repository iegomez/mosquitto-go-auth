package files

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/backends/topics"
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

// StaticFileUer keeps a user password and acl records.
type staticFileUser struct {
	password   string
	aclRecords []aclRecord
}

// aclRecord holds a topic and access privileges.
type aclRecord struct {
	topic string
	acc   byte //None 0x00, Read 0x01, Write 0x02, ReadWrite: Read | Write : 0x03, Subscribe 0x04, Deny 0x11
}

// Checker holds paths to static files, list of file users and general (no user or pattern) acl records.
type Checker struct {
	sync.Mutex
	pwPath          string
	aclPath         string
	checkACLs       bool
	checkUsers      bool
	users           map[string]*staticFileUser //users keeps a registry of username/staticFileUser pairs, holding a user's password and Acl records.
	aclRecords      []aclRecord
	staticFilesOnly bool
	hasher          hashing.HashComparer
	signals         chan os.Signal
}

// NewCheckers initializes a static files checker.
func NewChecker(backends, passwordPath, aclPath string, logLevel log.Level, hasher hashing.HashComparer) (*Checker, error) {

	log.SetLevel(logLevel)

	var checker = &Checker{
		pwPath:          passwordPath,
		aclPath:         aclPath,
		checkACLs:       true,
		users:           make(map[string]*staticFileUser),
		aclRecords:      make([]aclRecord, 0),
		staticFilesOnly: true,
		hasher:          hasher,
		signals:         make(chan os.Signal, 1),
		checkUsers:      true,
	}

	if checker.pwPath == "" {
		checker.checkUsers = false
		log.Infoln("[StaticFiles] passwords won't be checked")
	}

	if checker.aclPath == "" {
		checker.checkACLs = false
		log.Infoln("[StaticFiles] acls won't be checked")
	}

	if len(strings.Split(strings.Replace(backends, " ", "", -1), ",")) > 1 {
		checker.staticFilesOnly = false
	}

	err := checker.loadStaticFiles()
	if err != nil {
		return nil, err
	}

	go checker.watchSignals()

	return checker, nil
}

func (o *Checker) watchSignals() {
	signal.Notify(o.signals, syscall.SIGHUP)

	for {
		select {
		case sig := <-o.signals:
			if sig == syscall.SIGHUP {
				log.Debugln("[StaticFiles] got SIGHUP, reloading static files")
				o.loadStaticFiles()
			}
		}
	}
}

func (o *Checker) loadStaticFiles() error {
	o.Lock()
	defer o.Unlock()

	if o.checkUsers {
		count, err := o.readPasswords()
		if err != nil {
			return errors.Errorf("read passwords: %s", err)
		}

		log.Debugf("got %d users from passwords file", count)
	}

	if o.checkACLs {
		count, err := o.readAcls()
		if err != nil {
			return errors.Errorf("read acls: %s", err)
		}

		log.Debugf("got %d lines from acl file", count)
	}

	return nil
}

// ReadPasswords reads passwords file and populates static file users. Returns amount of users seen and possile error.
func (o *Checker) readPasswords() (int, error) {

	usersCount := 0

	file, err := os.Open(o.pwPath)
	if err != nil {
		return usersCount, fmt.Errorf("[StaticFiles] error: couldn't open passwords file: %s", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	index := 0
	for scanner.Scan() {
		index++

		text := scanner.Text()

		if checkCommentOrEmpty(text) {
			continue
		}

		lineArr := strings.Split(text, ":")
		if len(lineArr) != 2 {
			log.Errorf("Read passwords error: line %d is not well formatted", index)
			continue
		}

		var fileUser *staticFileUser
		var ok bool
		fileUser, ok = o.users[lineArr[0]]
		if ok {
			fileUser.password = lineArr[1]
		} else {
			usersCount++
			fileUser = &staticFileUser{
				password:   lineArr[1],
				aclRecords: make([]aclRecord, 0),
			}
			o.users[lineArr[0]] = fileUser
		}
	}

	return usersCount, nil

}

// readAcls reads the Acl file and associates them to existing users. It omits any non existing users.
func (o *Checker) readAcls() (int, error) {
	linesCount := 0
	currentUser := ""
	userExists := false
	userSeen := false

	file, err := os.Open(o.aclPath)
	if err != nil {
		return linesCount, errors.Errorf("StaticFiles backend error: couldn't open acl file: %s", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	index := 0

	for scanner.Scan() {
		index++

		text := scanner.Text()

		if checkCommentOrEmpty(text) {
			continue
		}

		line := strings.TrimSpace(text)

		lineArr := strings.Fields(line)
		prefix := lineArr[0]

		if prefix == "user" {
			// Flag that a user has been seen so no topic coming after is addigned to general ones.
			userSeen = true

			// Since there may be more than one consecutive space in the username, we have to remove the prefix and trim to get the username.
			username, err := removeAndTrim(prefix, line, index)
			if err != nil {
				return 0, err
			}

			_, ok := o.users[username]

			if !ok {
				if o.checkUsers {
					log.Warnf("user %s doesn't exist, skipping acls", username)
					// Flag username to skip topics later.
					userExists = false
					continue
				}

				o.users[username] = &staticFileUser{
					password:   "",
					aclRecords: make([]aclRecord, 0),
				}
			}

			userExists = true
			currentUser = username
		} else if prefix == "topic" || prefix == "pattern" {
			var aclRecord = aclRecord{
				topic: "",
				acc:   MOSQ_ACL_NONE,
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
				aclRecord.topic = lineArr[1]
				aclRecord.acc = MOSQ_ACL_READWRITE
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
					aclRecord.acc = permissions[permission]
				default:
					return 0, errors.Errorf("StaticFiles backend error: wrong acl format at line %d", index)
				}

				aclRecord.topic = topic
			}

			if prefix == "topic" {
				if currentUser != "" {
					// Skip topic when user was not found.
					if !userExists {
						continue
					}

					fUser, ok := o.users[currentUser]
					if !ok {
						return 0, errors.Errorf("StaticFiles backend error: user does not exist for acl at line %d", index)
					}
					fUser.aclRecords = append(fUser.aclRecords, aclRecord)
				} else {
					// Only append to general topics when no user has been processed.
					if !userSeen {
						o.aclRecords = append(o.aclRecords, aclRecord)
					}
				}
			} else {
				o.aclRecords = append(o.aclRecords, aclRecord)
			}

			linesCount++

		} else {
			return 0, errors.Errorf("StaticFiles backend error: wrong acl format at line %d", index)
		}
	}

	return linesCount, nil
}

func removeAndTrim(prefix, line string, index int) (string, error) {
	if len(line)-len(prefix) < 1 {
		return "", errors.Errorf("StaticFiles backend error: wrong acl format at line %d", index)
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

func (o *Checker) Users() map[string]*staticFileUser {
	return o.users
}

// GetUser checks that user exists and password is correct.
func (o *Checker) GetUser(username, password, clientid string) (bool, error) {

	fileUser, ok := o.users[username]
	if !ok {
		return false, nil
	}

	if o.hasher.Compare(password, fileUser.password) {
		return true, nil
	}

	log.Warnf("wrong password for user %s", username)

	return false, nil

}

// GetSuperuser returns false as there are no files superusers.
func (o *Checker) GetSuperuser(username string) (bool, error) {
	return false, nil
}

// CheckAcl checks that the topic may be read/written by the given user/clientid.
func (o *Checker) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	// If there are no acls and StaticFiles is the only backend, all access is allowed.
	// If there are other backends, then we can't blindly grant access.
	if !o.checkACLs {
		return o.staticFilesOnly, nil
	}

	fileUser, ok := o.users[username]

	// Check if the topic was explicitly denied and refuse to authorize if so.
	if ok {
		for _, aclRecord := range fileUser.aclRecords {
			match := topics.Match(aclRecord.topic, topic)

			if match {
				if aclRecord.acc == MOSQ_ACL_DENY {
					return false, nil
				}
			}
		}
	}

	for _, aclRecord := range o.aclRecords {
		aclTopic := strings.Replace(aclRecord.topic, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)

		match := topics.Match(aclTopic, topic)

		if match {
			if aclRecord.acc == MOSQ_ACL_DENY {
				return false, nil
			}
		}
	}

	// No denials, check against user's acls and common ones. If not authorized, check against pattern acls.
	if ok {
		for _, aclRecord := range fileUser.aclRecords {
			match := topics.Match(aclRecord.topic, topic)

			if match {
				if acc == int32(aclRecord.acc) || int32(aclRecord.acc) == MOSQ_ACL_READWRITE || (acc == MOSQ_ACL_SUBSCRIBE && topic != "#" && (int32(aclRecord.acc) == MOSQ_ACL_READ || int32(aclRecord.acc) == MOSQ_ACL_SUBSCRIBE)) {
					return true, nil
				}
			}
		}
	}
	for _, aclRecord := range o.aclRecords {
		// Replace all occurrences of %c for clientid and %u for username
		aclTopic := strings.Replace(aclRecord.topic, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)

		match := topics.Match(aclTopic, topic)

		if match {
			if acc == int32(aclRecord.acc) || int32(aclRecord.acc) == MOSQ_ACL_READWRITE || (acc == MOSQ_ACL_SUBSCRIBE && topic != "#" && (int32(aclRecord.acc) == MOSQ_ACL_READ || int32(aclRecord.acc) == MOSQ_ACL_SUBSCRIBE)) {
				return true, nil
			}
		}
	}

	return false, nil

}

// Halt does nothing for static files as there's no cleanup needed.
func (o *Checker) Halt() {
	// NO-OP
}
