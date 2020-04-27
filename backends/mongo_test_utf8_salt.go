package backends

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestMongo(t *testing.T) {

	//Initialize Mongo with some test values.
	authOpts := make(map[string]string)
	authOpts["mongo_host"] = "localhost"
	authOpts["mongo_port"] = "27017"
	//authOpts["mongo_username"] = "go_auth_test"
	//authOpts["mongo_password"] = "go_auth_test"
	//authOpts["mongo_authsource"] = "admin"
	authOpts["mongo_salt_encoding"] = "utf-8"
	authOpts["mongo_dbname"] = "mosquitto_test"

	Convey("Given valid params NewMongo should return a Mongo backend instance", t, func() {
		mongo, err := NewMongo(authOpts, log.DebugLevel)
		So(err, ShouldBeNil)

		//Drop DB and recreate it
		mongo.Conn.Database(mongo.DBName).Drop(context.TODO())
		mongoDb := mongo.Conn.Database(mongo.DBName)
		usersColl := mongoDb.Collection(mongo.UsersCollection)
		aclsColl := mongoDb.Collection(mongo.AclsCollection)

		//Insert a utf-8/ non-raw salt test user
		username := "test2"
		userPass := "testpw"
		//Utf-8 salt password hash, see: https://repl.it/repls/IntrepidHelpfulCable
		userPassHash := "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$dEOwgFUoMNt+Q8FHWXl03pZTg/RY47JdSTAx/KjhYKpbugOYg1WWG0tW0V2aqBnSCDLYJdRrkNf3p/PUoKLvkA=="

		//Create user and acls
		strictAcl := "test/topic/1"
		singleLevelAcl := "single/topic/+"
		hierarchyAcl := "hierarchy/#"

		userPattern := "pattern/%u"
		clientPattern := "pattern/%c"

		writeAcl := "write/test"
		readWriteAcl := "test/readwrite/1"

		testUser1 := MongoUser{
			Username:     username,
			PasswordHash: userPassHash,
			Superuser:    true,
			Acls: []MongoAcl{
				{Topic: strictAcl, Acc: 1},
				{Topic: singleLevelAcl, Acc: 1},
				{Topic: hierarchyAcl, Acc: 1},
				{Topic: writeAcl, Acc: 2},
				{Topic: readWriteAcl, Acc: 3},
			},
		}

		//mongo.Conn.Set(username, userPassHash, 0)
		usersColl.InsertOne(context.TODO(), &testUser1)
		usersColl.InsertOne(context.TODO(), &testUser2)

		Convey("Given username and a correct password, it should correctly authenticate it", func() {

			authenticated := mongo.GetUser(username, userPass, "")
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given username and an incorrect password, it should not authenticate it", func() {

			authenticated := mongo.GetUser(username, "wrong_password", "")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given username that is superuser, super user check should pass", func() {
			superuser := mongo.GetSuperuser(username)
			So(superuser, ShouldBeTrue)
		})

		clientID := "test_client"

		Convey("Given acls in DB, an exact match should work and and inexact one not matching wildcards not", func() {

			testTopic1 := `test/topic/1`
			testTopic2 := `not/matching/topic`

			tt1 := mongo.CheckAcl(username, testTopic1, clientID, MOSQ_ACL_READ)
			tt2 := mongo.CheckAcl(username, testTopic2, clientID, MOSQ_ACL_READ)

			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeFalse)

		})

		Convey("Given wildcard subscriptions that don't match user acls, acl checks should fail", func() {

			tt1 := mongo.CheckAcl(username, "not/matching/+", clientID, MOSQ_ACL_READ)
			tt2 := mongo.CheckAcl(username, "not/matching/#", clientID, MOSQ_ACL_READ)

			So(tt1, ShouldBeFalse)
			So(tt2, ShouldBeFalse)

		})

		userAcl := MongoAcl{
			Topic: userPattern,
			Acc:   1,
		}

		clientAcl := MongoAcl{
			Topic: clientPattern,
			Acc:   1,
		}

		aclsColl.InsertOne(context.TODO(), &userAcl)
		aclsColl.InsertOne(context.TODO(), &clientAcl)

		Convey("Given a topic that mentions username and subscribes to it, acl check should pass", func() {
			tt1 := mongo.CheckAcl(username, "pattern/test", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		Convey("Given a topic that mentions clientid, acl check should pass", func() {
			tt1 := mongo.CheckAcl(username, "pattern/test_client", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		Convey("Given a topic not strictly present that matches a db single level wildcard, acl check should pass", func() {
			tt1 := mongo.CheckAcl(username, "single/topic/whatever", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		Convey("Given a topic that matches single level but has more levels, acl check should not pass", func() {
			tt1 := mongo.CheckAcl(username, "single/topic/whatever/extra", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeFalse)
		})

		Convey("Given a topic not strictly present that matches a hierarchy wildcard, acl check should pass", func() {
			tt1 := mongo.CheckAcl(username, "hierarchy/what/ever", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		//Now test against a publish subscription
		Convey("Given a publish attempt for a read only acl, acl check should fail", func() {
			tt1 := mongo.CheckAcl(username, strictAcl, clientID, MOSQ_ACL_WRITE)
			So(tt1, ShouldBeFalse)
		})

		Convey("Given a subscription attempt on a write only acl, acl check should fail", func() {
			tt1 := mongo.CheckAcl(username, writeAcl, clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeFalse)
		})

		Convey("Given a sub/pub attempt on a readwrite acl, acl check should pass for both", func() {
			tt1 := mongo.CheckAcl(username, readWriteAcl, clientID, MOSQ_ACL_READ)
			tt2 := mongo.CheckAcl(username, readWriteAcl, clientID, MOSQ_ACL_WRITE)
			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeTrue)
		})

		//Empty db
		mongoDb.Drop(context.TODO())

		mongo.Halt()

	})

}
