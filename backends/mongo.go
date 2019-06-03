package backends

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"

	"github.com/iegomez/mosquitto-go-auth/common"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Mongo struct {
	Host            string
	Port            string
	Username        string
	Password        string
	DBName          string
	UsersCollection string
	AclsCollection  string
	Conn            *mgo.Session
}

type MongoAcl struct {
	Topic string `bson:"topic"`
	Acc   int32  `bson:"acc"`
}

type MongoUser struct {
	Username     string     `bson:"username"`
	PasswordHash string     `bson:"password"`
	Superuser    bool       `bson:"superuser"`
	Acls         []MongoAcl `bson:"acls"`
}

func NewMongo(authOpts map[string]string, logLevel log.Level) (Mongo, error) {

	log.SetLevel(logLevel)

	var mongo = Mongo{
		Host:            "localhost",
		Port:            "27017",
		Username:        "",
		Password:        "",
		DBName:          "mosquitto",
		UsersCollection: "users",
		AclsCollection:  "acls",
	}

	if mongoHost, ok := authOpts["mongo_host"]; ok {
		mongo.Host = mongoHost
	}

	if mongoPort, ok := authOpts["mongo_port"]; ok {
		mongo.Port = mongoPort
	}

	if mongoUsername, ok := authOpts["mongo_username"]; ok {
		mongo.Username = mongoUsername
	}

	if mongoPassword, ok := authOpts["mongo_password"]; ok {
		mongo.Password = mongoPassword
	}

	if mongoDBName, ok := authOpts["mongo_dbname"]; ok {
		mongo.DBName = mongoDBName
	}

	if usersCollection, ok := authOpts["mongo_users"]; ok {
		mongo.UsersCollection = usersCollection
	}

	if aclsCollection, ok := authOpts["mongo_acls"]; ok {
		mongo.AclsCollection = aclsCollection
	}

	addr := fmt.Sprintf("%s:%s", mongo.Host, mongo.Port)

	mongoDBDialInfo := &mgo.DialInfo{
		Addrs:    []string{addr},
		Timeout:  60 * time.Second,
		Database: mongo.DBName,
	}

	if mongo.Username != "" && mongo.Password != "" {
		mongoDBDialInfo.Username = mongo.Username
		mongoDBDialInfo.Password = mongo.Password
	}

	mongoSession, err := mgo.DialWithInfo(mongoDBDialInfo)
	if err != nil {
		return mongo, errors.Errorf("couldn't start mongo backend. error: %s\n", err)
	}

	mongoSession.SetMode(mgo.Monotonic, true)

	mongo.Conn = mongoSession

	return mongo, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Mongo) GetUser(username, password string) bool {

	uc := o.Conn.DB(o.DBName).C(o.UsersCollection)

	var user MongoUser

	err := uc.Find(bson.M{"username": username}).One(&user)
	if err != nil {
		log.Debugf("Mongo get user error: %s", err)
		return false
	}

	if common.HashCompare(password, user.PasswordHash) {
		return true
	}

	return false

}

//GetSuperuser checks that the key username:su exists and has value "true".
func (o Mongo) GetSuperuser(username string) bool {

	uc := o.Conn.DB(o.DBName).C(o.UsersCollection)

	var user MongoUser

	err := uc.Find(bson.M{"username": username}).One(&user)
	if err != nil {
		log.Debugf("Mongo get superuser error: %s", err)
		return false
	}

	return user.Superuser

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Mongo) CheckAcl(username, topic, clientid string, acc int32) bool {

	//Get user and check his acls.
	uc := o.Conn.DB(o.DBName).C(o.UsersCollection)

	var user MongoUser

	err := uc.Find(bson.M{"username": username}).One(&user)
	if err != nil {
		log.Debugf("Mongo get superuser error: %s", err)
		return false
	}

	for _, acl := range user.Acls {
		if (acl.Acc == acc || acl.Acc == 3) && common.TopicsMatch(acl.Topic, topic) {
			return true
		}
	}

	//Now check common acls.

	ac := o.Conn.DB(o.DBName).C(o.AclsCollection)

	var acls []MongoAcl

	//aErr := ac.Find(bson.M{"$or": []bson.M{bson.M{"acc": acc}, bson.M{"acc": 3}}}).All(&acls)
	aErr := ac.Find(bson.M{"acc": bson.M{"$in": []int32{acc, 3}}}).All(&acls)
	//aErr := ac.

	if aErr != nil {
		log.Debugf("Mongo check acl error: %s", err)
		return false
	}

	for _, acl := range acls {
		aclTopic := strings.Replace(acl.Topic, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)
		if common.TopicsMatch(aclTopic, topic) {
			return true
		}
	}

	return false

}

//GetName returns the backend's name
func (o Mongo) GetName() string {
	return "Mongo"
}

//Halt closes the mongo session.
func (o Mongo) Halt() {
	if o.Conn != nil {
		o.Conn.Close()
	}
}
