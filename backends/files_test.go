package backends

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestFiles(t *testing.T) {
	//Initialize Files with mock password and acl files.
	authOpts := make(map[string]string)

	Convey("Given empty opts NewFiles should fail", t, func() {
		files, err := NewFiles(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "files"))
		So(err, ShouldBeError)

		files.Halt()
	})

	pwPath, _ := filepath.Abs("../test-files/passwords")
	aclPath, _ := filepath.Abs("../test-files/acls")
	authOpts["password_path"] = pwPath
	authOpts["acl_path"] = aclPath
	clientID := "test_client"

	Convey("Given valid params NewFiles should return a new files backend instance", t, func() {
		files, err := NewFiles(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "files"))
		So(err, ShouldBeNil)

		/*
			ACL file looks like this:

			topic test/general
			topic deny test/general_denied

			user test1
			topic write test/topic/1
			topic read test/topic/2

			user test2
			topic read test/topic/+

			user test3
			topic read test/#
			topic deny test/denied

			user test with space
			topic  test/space
			topic read test/multiple spaces in/topic
			 topic   read   test/lots   of   spaces   in/topic and borders

			user not_present
			topic read test/not_present

			pattern read test/%u
			pattern read test/%c
		*/

		// passwords are the same as users,
		// except for user4 that's not present in passwords and should be skipped when reading acls
		user1 := "test1"
		user2 := "test2"
		user3 := "test3"
		user4 := "not_present"
		elton := "test with space" // You know, because he's a rocket man. Ok, I'll let myself out.

		generalTopic := "test/general"
		generalDeniedTopic := "test/general_denied"

		Convey("All users but not present ones should have a record", func() {
			_, ok := files.Users[user1]
			So(ok, ShouldBeTrue)

			_, ok = files.Users[user2]
			So(ok, ShouldBeTrue)

			_, ok = files.Users[user3]
			So(ok, ShouldBeTrue)

			_, ok = files.Users[user4]
			So(ok, ShouldBeFalse)

			_, ok = files.Users[elton]
			So(ok, ShouldBeTrue)
		})

		Convey("All users should be able to read the general topic", func() {
			authenticated, err := files.CheckAcl(user1, generalTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)

			authenticated, err = files.CheckAcl(user2, generalTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)

			authenticated, err = files.CheckAcl(user3, generalTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)

			authenticated, err = files.CheckAcl(elton, generalTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)
		})

		Convey("No user should be able to read the general denied topic", func() {
			authenticated, err := files.CheckAcl(user1, generalDeniedTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeFalse)

			authenticated, err = files.CheckAcl(user2, generalDeniedTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeFalse)

			authenticated, err = files.CheckAcl(user3, generalDeniedTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeFalse)

			authenticated, err = files.CheckAcl(elton, generalDeniedTopic, clientID, 1)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeFalse)
		})

		Convey("Given a username and a correct password, it should correctly authenticate it", func() {
			authenticated, err := files.GetUser(user1, user1, clientID)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)

			authenticated, err = files.GetUser(user2, user2, clientID)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)

			authenticated, err = files.GetUser(user3, user3, clientID)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)

			authenticated, err = files.GetUser(elton, elton, clientID)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeTrue)
		})

		Convey("Given a username and an incorrect password, it should not authenticate it", func() {
			authenticated, err := files.GetUser(user1, user2, clientID)
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeFalse)
		})

		Convey("Given a wrong username, it should not authenticate it and not return error", func() {
			authenticated, err := files.GetUser(user4, "whatever_password", "")
			So(err, ShouldBeNil)
			So(authenticated, ShouldBeFalse)
		})

		//There are no superusers for files
		Convey("For any user superuser should return false", func() {
			superuser, err := files.GetSuperuser(user1)
			So(err, ShouldBeNil)
			So(superuser, ShouldBeFalse)

			Convey("Including non-present username", func() {
				superuser, err := files.GetSuperuser(user4)
				So(err, ShouldBeNil)
				So(superuser, ShouldBeFalse)
			})
		})

		testTopic1 := `test/topic/1`
		testTopic2 := `test/topic/2`
		testTopic3 := `test/other/1`
		testTopic4 := `other/1`
		readWriteTopic := "readwrite/topic"
		spaceTopic := "test/space"
		multiSpaceTopic := "test/multiple spaces in/topic"
		lotsOfSpacesTopic := "test/lots   of   spaces   in/topic and borders"
		deniedTopic := "test/denied"

		Convey("Topics for non existing users should be ignored", func() {
			for record := range files.AclRecords {
				So(record, ShouldNotEqual, "test/not_present")
			}

			for _, user := range files.Users {
				for record := range user.AclRecords {
					So(record, ShouldNotEqual, "test/not_present")
				}
			}
		})

		Convey("User 1 should be able to publish and not subscribe to test topic 1, and only subscribe but not publish to topic 2", func() {
			tt1, err1 := files.CheckAcl(user1, testTopic1, clientID, 2)
			tt2, err2 := files.CheckAcl(user1, testTopic1, clientID, 1)
			tt3, err3 := files.CheckAcl(user1, testTopic2, clientID, 2)
			tt4, err4 := files.CheckAcl(user1, testTopic2, clientID, 1)

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)
			So(err4, ShouldBeNil)
			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeFalse)
			So(tt3, ShouldBeFalse)
			So(tt4, ShouldBeTrue)
		})

		Convey("User 1 should be able to subscribe or publish to a readwrite topic rule", func() {
			tt1, err1 := files.CheckAcl(user1, readWriteTopic, clientID, 2)
			tt2, err2 := files.CheckAcl(user1, readWriteTopic, clientID, 1)
			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeTrue)
		})

		Convey("User 2 should be able to read any test/topic/X but not any/other", func() {
			tt1, err1 := files.CheckAcl(user2, testTopic1, clientID, 1)
			tt2, err2 := files.CheckAcl(user2, testTopic2, clientID, 1)
			tt3, err3 := files.CheckAcl(user2, testTopic3, clientID, 1)

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)
			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeTrue)
			So(tt3, ShouldBeFalse)
		})

		Convey("User 3 should be able to read any test/X but not other/... nor test/denied\n\n", func() {
			fmt.Printf("\n\nUser 3 acls: %#v", files.Users[user3].AclRecords)
			tt1, err1 := files.CheckAcl(user3, testTopic1, clientID, 1)
			tt2, err2 := files.CheckAcl(user3, testTopic2, clientID, 1)
			tt3, err3 := files.CheckAcl(user3, testTopic3, clientID, 1)
			tt4, err4 := files.CheckAcl(user3, testTopic4, clientID, 1)
			tt5, err5 := files.CheckAcl(user3, deniedTopic, clientID, 1)

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)
			So(err4, ShouldBeNil)
			So(err5, ShouldBeNil)
			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeTrue)
			So(tt3, ShouldBeTrue)
			So(tt4, ShouldBeFalse)
			So(tt5, ShouldBeFalse)
		})

		Convey("User 4 should not be able to read since it's not in the passwords file", func() {
			tt1, err1 := files.CheckAcl(user4, testTopic1, clientID, 1)

			So(err1, ShouldBeNil)
			So(tt1, ShouldBeFalse)
		})

		Convey("Elton Bowie should be able to read and write to `test/space`, and only read from other topics", func() {
			tt1, err1 := files.CheckAcl(elton, spaceTopic, clientID, 2)
			tt2, err2 := files.CheckAcl(elton, multiSpaceTopic, clientID, 1)
			tt3, err3 := files.CheckAcl(elton, multiSpaceTopic, clientID, 2)
			tt4, err4 := files.CheckAcl(elton, lotsOfSpacesTopic, clientID, 1)
			tt5, err5 := files.CheckAcl(elton, lotsOfSpacesTopic, clientID, 2)

			So(err1, ShouldBeNil)
			So(err2, ShouldBeNil)
			So(err3, ShouldBeNil)
			So(err4, ShouldBeNil)
			So(err5, ShouldBeNil)
			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeTrue)
			So(tt3, ShouldBeFalse)
			So(tt4, ShouldBeTrue)
			So(tt5, ShouldBeFalse)
		})

		//Now check against patterns.
		Convey("Given a topic that mentions username, acl check should pass", func() {
			tt1, err1 := files.CheckAcl(user1, "test/test1", clientID, 1)
			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)

			tt2, err2 := files.CheckAcl(elton, "test/test with space", clientID, 1)
			So(err2, ShouldBeNil)
			So(tt2, ShouldBeTrue)
		})

		Convey("Given a topic that mentions clientid, acl check should pass", func() {
			tt1, err1 := files.CheckAcl(user1, "test/test_client", clientID, 1)
			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)
		})

		//Halt files
		files.Halt()
	})

	Convey("On SIGHUP files should be reloaded", t, func() {
		pwFile, err := os.Create("../test-files/test-passwords")
		So(err, ShouldBeNil)
		aclFile, err := os.Create("../test-files/test-acls")
		So(err, ShouldBeNil)

		defer os.Remove(pwFile.Name())
		defer os.Remove(aclFile.Name())

		hasher := hashing.NewHasher(authOpts, "files")

		user1 := "test1"
		user2 := "test2"

		pw1, err := hasher.Hash(user1)
		So(err, ShouldBeNil)

		pw2, err := hasher.Hash(user2)
		So(err, ShouldBeNil)

		pwFile.WriteString(fmt.Sprintf("\n%s:%s\n", user1, pw1))

		aclFile.WriteString("\nuser test1")
		aclFile.WriteString("\ntopic read test/#")

		pwFile.Sync()
		aclFile.Sync()

		authOpts["password_path"] = pwFile.Name()
		authOpts["acl_path"] = aclFile.Name()

		files, err := NewFiles(authOpts, log.DebugLevel, hasher)
		So(err, ShouldBeNil)

		user, ok := files.Users[user1]
		So(ok, ShouldBeTrue)

		record := user.AclRecords[0]
		So(record.Acc, ShouldEqual, MOSQ_ACL_READ)
		So(record.Topic, ShouldEqual, "test/#")

		_, ok = files.Users[user2]
		So(ok, ShouldBeFalse)

		// Now add second user and reload.
		pwFile.WriteString(fmt.Sprintf("\n%s:%s\n", user2, pw2))

		aclFile.WriteString("\nuser test2")
		aclFile.WriteString("\ntopic write test/#")

		files.signals <- syscall.SIGHUP

		time.Sleep(200 * time.Millisecond)

		user, ok = files.Users[user2]
		So(ok, ShouldBeTrue)

		record = user.AclRecords[0]
		So(record.Acc, ShouldEqual, MOSQ_ACL_WRITE)
		So(record.Topic, ShouldEqual, "test/#")
	})
}
