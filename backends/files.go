package backends

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

//FileUer keeps a user password and acl records.
type FileUser struct {
	Password   string
	ACLRecords []ACLRecord
}

//ACLRecord holds nd array of acl access records.
type ACLRecord struct {
	ClientID string
	Topic    string
	ACC      int32 //Read 0, Write 1
}

//FileBE holds paths to files, list of passwords and acl records.
type Files struct {
	PasswordPath string
	ACLPath      string
	Users        map[string]*FileUser //Users keeps a registry of username/FileUser pairs, holding a user's password and ACL records.
}

//NewFiles initializes a files backend.
func NewFiles(authOpts map[string]string) (Files, error) {

	var files = Files{
		PasswordPath: "",
		ACLPath:      "",
		Users:        make(map[string]FileUser),
	}

	if passwordPath, ok := authOpts["password_path"]; ok {
		files.PasswordPath = passwordPath
	} else {
		log.Fatal("Files backend error: no password path given.\n")
	}

	if aclPath, ok := authOpts["acl_path"]; ok {
		files.ACLPath = aclPath
	} else {
		log.Fatal("Files backend error: no password path given.\n")
	}

	//Now initialize FileUsers by reading from password and acl files.

}

//ReadPasswords read file and populates FileUsers. Return amount of users seen and possile error.
func (o Files) ReadPasswords() (int, error) {

	usersCount := 0

	file, fErr := os.Open(o.PasswordPath)
	defer file.Close()
	if fErr != nil {
		return usersCount, fmt.Errorf("Files backend error: couldn't open passwords file: %s\n", fErr)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	index := 0
	//Read line by line
	for scanner.Scan() {
		index++
		lineArr := strings.Split(scanner.Text(), ":")
		if len(lineArr) != 2 {
			log.Errorf("Read passwords error: line %d is not well formatted.\n", index)
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
			fileUser = *FileUser{
				Password:   lineArr[1],
				ACLRecords: make([]ACLRecord, 3, 3),
			}
			o.Users[lineArr[0]] = fileUser
		}
	}

	return usersCount, nil

}

//ReadACLs reads the ACL file and associates them to existing users. It omits any non existing users.
func (o Files) ReadACLs() (int, error) {

	linesCount := 0

	//Set currentUser as empty string
	currentUser := ""

	file, fErr := os.Open(o.PasswordPath)
	defer file.Close()
	if fErr != nil {
		return usersCount, fmt.Errorf("Files backend error: couldn't open acl file: %s\n", fErr)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	index := 0

	for scanner.Scan() {
		index++
		line := scanner.Text()

		//If we see a user line, change the current user.
		if strings.Contains(line, "user") {
			//Try to get username
			lineArr := strings.Fields(line)

			//Check format
			if len(lineArr) == 2 && lineArr[0] == "user" {
				_, ok := o.Users[lineArr[1]]

				//Check that user exists
				if !ok {
					log.Fatalf("Files backend error: user %s does not exist, omitting acl at line %d\n", lineArr[1], index)

				}

				currentUser = lineArr[1]

			} else {
				log.Fatalf("Files backend error: bad acl format, omitting user at line %d\n", index)

			}
		} else if strings.Contains(line, "topic") {
			var aclRecord _ = ACLRecord{
				ClientID: "",
				Topic:    "",
				Acc:      0,
			}
		}
	}

}
