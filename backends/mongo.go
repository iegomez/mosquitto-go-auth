package backends

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Mongo struct {
	Host               string
	Port               string
	Username           string
	Password           string
	SaltEncoding       string
	DBName             string
	AuthSource         string
	UsersCollection    string
	AclsCollection     string
	Conn               *mongo.Client
	disableSuperuser   bool
	hasher             hashing.HashComparer
	withTLS            bool
	insecureSkipVerify bool
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

func NewMongo(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (Mongo, error) {

	log.SetLevel(logLevel)

	var m = Mongo{
		Host:               "localhost",
		Port:               "27017",
		Username:           "",
		Password:           "",
		DBName:             "mosquitto",
		AuthSource:         "",
		UsersCollection:    "users",
		AclsCollection:     "acls",
		hasher:             hasher,
		withTLS:            false,
		insecureSkipVerify: false,
	}

	if authOpts["mongo_disable_superuser"] == "true" {
		m.disableSuperuser = true
	}

	if mongoHost, ok := authOpts["mongo_host"]; ok {
		m.Host = mongoHost
	}

	if mongoPort, ok := authOpts["mongo_port"]; ok {
		m.Port = mongoPort
	}

	if mongoUsername, ok := authOpts["mongo_username"]; ok {
		m.Username = mongoUsername
	}

	if mongoPassword, ok := authOpts["mongo_password"]; ok {
		m.Password = mongoPassword
	}

	if mongoDBName, ok := authOpts["mongo_dbname"]; ok {
		m.DBName = mongoDBName
	}

	if mongoAuthSource, ok := authOpts["mongo_authsource"]; ok {
		m.AuthSource = mongoAuthSource
	}

	if usersCollection, ok := authOpts["mongo_users"]; ok {
		m.UsersCollection = usersCollection
	}

	if aclsCollection, ok := authOpts["mongo_acls"]; ok {
		m.AclsCollection = aclsCollection
	}

	if authOpts["mongo_use_tls"] == "true" {
		m.withTLS = true
	}

	if authOpts["mongo_insecure_skip_verify"] == "true" {
		m.insecureSkipVerify = true
	}

	addr := fmt.Sprintf("mongodb://%s:%s", m.Host, m.Port)

	to := 60 * time.Second

	opts := options.ClientOptions{
		ConnectTimeout: &to,
	}

	if m.withTLS {
		opts.TLSConfig = &tls.Config{}
	}

	opts.ApplyURI(addr)

	if m.Username != "" && m.Password != "" {
		opts.Auth = &options.Credential{
			AuthSource:  m.DBName,
			Username:    m.Username,
			Password:    m.Password,
			PasswordSet: true,
		}
		// Set custom AuthSource db if supplied in config
		if m.AuthSource != "" {
			opts.Auth.AuthSource = m.AuthSource
			log.Infof("mongo backend: set authentication db to: %s", m.AuthSource)
		}
	}

	client, err := mongo.Connect(context.TODO(), &opts)
	if err != nil {
		return m, errors.Errorf("couldn't start mongo backend: %s", err)
	}

	m.Conn = client

	return m, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Mongo) GetUser(username, password, clientid string) (bool, error) {

	uc := o.Conn.Database(o.DBName).Collection(o.UsersCollection)

	var user MongoUser

	err := uc.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// avoid leaking the fact that user exists or not though error.
			return false, nil
		}

		log.Debugf("Mongo get user error: %s", err)
		return false, err
	}

	if o.hasher.Compare(password, user.PasswordHash) {
		return true, nil
	}

	return false, nil

}

//GetSuperuser checks that the key username:su exists and has value "true".
func (o Mongo) GetSuperuser(username string) (bool, error) {

	if o.disableSuperuser {
		return false, nil
	}

	uc := o.Conn.Database(o.DBName).Collection(o.UsersCollection)

	var user MongoUser

	err := uc.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// avoid leaking the fact that user exists or not though error.
			return false, nil
		}

		log.Debugf("Mongo get superuser error: %s", err)
		return false, err
	}

	return user.Superuser, nil

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Mongo) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	//Get user and check his acls.
	uc := o.Conn.Database(o.DBName).Collection(o.UsersCollection)

	var user MongoUser

	err := uc.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// avoid leaking the fact that user exists or not though error.
			return false, nil
		}

		log.Debugf("Mongo get superuser error: %s", err)
		return false, err
	}

	for _, acl := range user.Acls {
		// TODO: needs fixing since it's bypassing MOSQ_ACL_SUBSCRIBE.
		if (acl.Acc == acc || acl.Acc == MOSQ_ACL_READWRITE) && topics.Match(acl.Topic, topic) {
			return true, nil
		}
	}

	//Now check common acls.

	ac := o.Conn.Database(o.DBName).Collection(o.AclsCollection)
	cur, err := ac.Find(context.TODO(), bson.M{"acc": bson.M{"$in": []int32{acc, 3}}})

	if err != nil {
		log.Debugf("Mongo check acl error: %s", err)
		return false, err
	}

	defer cur.Close(context.TODO())

	for cur.Next(context.TODO()) {
		var acl MongoAcl
		err = cur.Decode(&acl)
		if err == nil {
			aclTopic := strings.Replace(acl.Topic, "%c", clientid, -1)
			aclTopic = strings.Replace(aclTopic, "%u", username, -1)
			if topics.Match(aclTopic, topic) {
				return true, nil
			}
		} else {
			log.Errorf("mongo cursor decode error: %s", err)
		}
	}

	return false, nil

}

//GetName returns the backend's name
func (o Mongo) GetName() string {
	return "Mongo"
}

//Halt closes the mongo session.
func (o Mongo) Halt() {
	if o.Conn != nil {
		err := o.Conn.Disconnect(context.TODO())
		if err != nil {
			log.Errorf("mongo halt: %s", err)
		}
	}
}
