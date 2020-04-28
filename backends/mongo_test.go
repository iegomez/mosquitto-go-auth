package backends

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

// Mongo Connection Details
const mongoHost = "localhost"
const mongoPort = "27017"
const mongoDbName = "mosquitto_test"

//MQTT ACL Patterns
const strictAcl = "test/topic/1"
const singleLevelAcl = "single/topic/+"
const hierarchyAcl = "hierarchy/#"
const userPattern = "pattern/%u"
const clientPattern = "pattern/%c"
const writeAcl = "write/test"
const readWriteAcl = "test/readwrite/1"

//Define Users, username1 is RAW salt, username2 is UTF-8 salt
const username1 = "test"
const userPass1 = "testpw"
const userPassHash1 = "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$BK1BQ2wbwU1zNxv3Ml3wLuu5//hPop3/LvaPYjjCwdBvnpwusnukJPpcXQzyyjOlZdieXTx6sXAcX4WnZRZZnw=="
const username2 = "test2"
const userPass2 = "testpw"
const userPassHash2 = "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$dEOwgFUoMNt+Q8FHWXl03pZTg/RY47JdSTAx/KjhYKpbugOYg1WWG0tW0V2aqBnSCDLYJdRrkNf3p/PUoKLvkA=="

//////////////////////////////////////////////////////  First Run, RAW salt and full testing
func TestMongoRaw(t *testing.T) {
	//Define Common Mongo Configuration
	var authOpts = make(map[string]string)
	authOpts["mongo_host"] = mongoHost
	authOpts["mongo_port"] = mongoPort
	authOpts["mongo_dbname"] = mongoDbName
	//authOpts["mongo_username"] = "go_auth_test"
	//authOpts["mongo_password"] = "go_auth_test"
	//authOpts["mongo_authsource"] = "admin"
	mongo, err := NewMongo(authOpts, log.DebugLevel)
	So(err, ShouldBeNil)
	mongo.Conn.Database(mongo.DBName).Drop(context.TODO())
	mongoDb := mongo.Conn.Database(mongo.DBName)
	usersColl := mongoDb.Collection(mongo.UsersCollection)
	aclsColl := mongoDb.Collection(mongo.AclsCollection)

	Convey("Given username1 params usersColl.InsertOne should return true", t, func() {
		testUser := MongoUser{
			Username:     username1,
			PasswordHash: userPassHash1,
			Superuser:    true,
			Acls: []MongoAcl{
				{Topic: strictAcl, Acc: 1},
				{Topic: singleLevelAcl, Acc: 1},
				{Topic: hierarchyAcl, Acc: 1},
				{Topic: writeAcl, Acc: 2},
				{Topic: readWriteAcl, Acc: 3},
			},
		}
		insertResult, err := usersColl.InsertOne(context.TODO(), &testUser)
		So(insertResult.InsertedID, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})
	Convey("Given username2 params usersColl.InsertOne should return true", t, func() {
		testUser := MongoUser{
			Username:     username2,
			PasswordHash: userPassHash2,
			Superuser:    true,
			Acls: []MongoAcl{
				{Topic: strictAcl, Acc: 1},
				{Topic: singleLevelAcl, Acc: 1},
				{Topic: hierarchyAcl, Acc: 1},
				{Topic: writeAcl, Acc: 2},
				{Topic: readWriteAcl, Acc: 3},
			},
		}
		insertResult, err := usersColl.InsertOne(context.TODO(), &testUser)
		So(insertResult.InsertedID, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("Given username1 and a correct password, it should correctly authenticate it", func() {
		authenticated := mongo.GetUser(username1, userPass1, "")
		So(authenticated, ShouldBeTrue)
	})
	Convey("Given username1 and an incorrect password, it should not authenticate it", func() {
		authenticated := mongo.GetUser(username1, "wrong_password", "")
		So(authenticated, ShouldBeFalse)
	})
	Convey("Given username1 that is superuser, super user check should pass", func() {
		superuser := mongo.GetSuperuser(username1)
		So(superuser, ShouldBeTrue)
	})
	Convey("Given correct username2 password, but using wrong salt format, user should not authenticate", func() {
		authenticated := mongo.GetUser(username2, userPass2, "")
		So(authenticated, ShouldBeFalse)
	})
	clientID := "test_client"
	Convey("Given acls in DB, an exact match should work and and inexact one not matching wildcards not", func() {
		testTopic1 := `test/topic/1`
		testTopic2 := `not/matching/topic`
		tt1 := mongo.CheckAcl(username1, testTopic1, clientID, MOSQ_ACL_READ)
		tt2 := mongo.CheckAcl(username1, testTopic2, clientID, MOSQ_ACL_READ)
		So(tt1, ShouldBeTrue)
		So(tt2, ShouldBeFalse)
	})
	Convey("Given wildcard subscriptions that don't match user acls, acl checks should fail", func() {
		tt1 := mongo.CheckAcl(username1, "not/matching/+", clientID, MOSQ_ACL_READ)
		tt2 := mongo.CheckAcl(username1, "not/matching/#", clientID, MOSQ_ACL_READ)
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
		tt1 := mongo.CheckAcl(username1, "pattern/test", clientID, MOSQ_ACL_READ)
		So(tt1, ShouldBeTrue)
	})
	Convey("Given a topic that mentions clientid, acl check should pass", func() {
		tt1 := mongo.CheckAcl(username1, "pattern/test_client", clientID, MOSQ_ACL_READ)
		So(tt1, ShouldBeTrue)
	})
	Convey("Given a topic not strictly present that matches a db single level wildcard, acl check should pass", func() {
		tt1 := mongo.CheckAcl(username1, "single/topic/whatever", clientID, MOSQ_ACL_READ)
		So(tt1, ShouldBeTrue)
	})
	Convey("Given a topic that matches single level but has more levels, acl check should not pass", func() {
		tt1 := mongo.CheckAcl(username1, "single/topic/whatever/extra", clientID, MOSQ_ACL_READ)
		So(tt1, ShouldBeFalse)
	})
	Convey("Given a topic not strictly present that matches a hierarchy wildcard, acl check should pass", func() {
		tt1 := mongo.CheckAcl(username1, "hierarchy/what/ever", clientID, MOSQ_ACL_READ)
		So(tt1, ShouldBeTrue)
	})
	//Now test against a publish subscription
	Convey("Given a publish attempt for a read only acl, acl check should fail", func() {
		tt1 := mongo.CheckAcl(username1, strictAcl, clientID, MOSQ_ACL_WRITE)
		So(tt1, ShouldBeFalse)
	})
	Convey("Given a subscription attempt on a write only acl, acl check should fail", func() {
		tt1 := mongo.CheckAcl(username1, writeAcl, clientID, MOSQ_ACL_READ)
		So(tt1, ShouldBeFalse)
	})
	Convey("Given a sub/pub attempt on a readwrite acl, acl check should pass for both", func() {
		tt1 := mongo.CheckAcl(username1, readWriteAcl, clientID, MOSQ_ACL_READ)
		tt2 := mongo.CheckAcl(username1, readWriteAcl, clientID, MOSQ_ACL_WRITE)
		So(tt1, ShouldBeTrue)
		So(tt2, ShouldBeTrue)
	})

	mongoDb.Drop(context.TODO())
	mongo.Halt()
}

//////////////////////////////////////////////////////  Second Run, UTF-8 salt and basic testing
func TestMongoUtf8(t *testing.T) {
	//////////  MongoDB Setup
	//Define Common Mongo Configuration
	var authOpts = make(map[string]string)
	authOpts["mongo_host"] = mongoHost
	authOpts["mongo_port"] = mongoPort
	authOpts["mongo_dbname"] = mongoDbName
	//authOpts["mongo_username"] = "go_auth_test"
	//authOpts["mongo_password"] = "go_auth_test"
	//authOpts["mongo_authsource"] = "admin"
	authOpts["mongo_salt_encoding"] = "utf-8"
	mongo, err := NewMongo(authOpts, log.DebugLevel)
	So(err, ShouldBeNil)
	mongo.Conn.Database(mongo.DBName).Drop(context.TODO())
	mongoDb := mongo.Conn.Database(mongo.DBName)
	usersColl := mongoDb.Collection(mongo.UsersCollection)
	aclsColl := mongoDb.Collection(mongo.AclsCollection)
	Convey("Given username1 params usersColl.InsertOne should return true", t, func() {
		testUser := MongoUser{
			Username:     username1,
			PasswordHash: userPassHash1,
			Superuser:    true,
			Acls: []MongoAcl{
				{Topic: strictAcl, Acc: 1},
				{Topic: singleLevelAcl, Acc: 1},
				{Topic: hierarchyAcl, Acc: 1},
				{Topic: writeAcl, Acc: 2},
				{Topic: readWriteAcl, Acc: 3},
			},
		}
		insertResult, err := usersColl.InsertOne(context.TODO(), &testUser)
		So(insertResult.InsertedID, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})
	Convey("Given username2 params usersColl.InsertOne should return true", t, func() {
		testUser := MongoUser{
			Username:     username2,
			PasswordHash: userPassHash2,
			Superuser:    true,
			Acls: []MongoAcl{
				{Topic: strictAcl, Acc: 1},
				{Topic: singleLevelAcl, Acc: 1},
				{Topic: hierarchyAcl, Acc: 1},
				{Topic: writeAcl, Acc: 2},
				{Topic: readWriteAcl, Acc: 3},
			},
		}
		insertResult, err := usersColl.InsertOne(context.TODO(), &testUser)
		So(insertResult.InsertedID, ShouldNotBeNil)
		So(err, ShouldBeNil)
	})

	Convey("Given username2 and a correct password, it should correctly authenticate it", func() {
		authenticated := mongo.GetUser(username2, userPass2, "")
		So(authenticated, ShouldBeTrue)
	})
	Convey("Given username2 and an incorrect password, it should not authenticate it", func() {
		authenticated := mongo.GetUser(username2, "wrong_password", "")
		So(authenticated, ShouldBeFalse)
	})
	Convey("Given username2 that is superuser, super user check should pass", func() {
		superuser := mongo.GetSuperuser(username2)
		So(superuser, ShouldBeTrue)
	})
	Convey("Given correct username1 password, but using wrong salt format, user should not authenticate", func() {
		authenticated := mongo.GetUser(username1, userPass1, "")
		So(authenticated, ShouldBeFalse)
	})

	mongoDb.Drop(context.TODO())
	mongo.Halt()
}