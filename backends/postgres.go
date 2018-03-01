package backends

import (
	"database/sql"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"

	"github.com/iegomez/mosquitto-go-auth/common"
)

//Postgres holds all fields of the postgres db connection.
type Postgres struct {
	DB             *sqlx.DB
	Host           string
	Port           string
	DBName         string
	User           string
	Password       string
	UserQuery      string
	SuperuserQuery string
	AclQuery       string
	SSLMode        string
	SSLCert        string
	SSLKey         string
	SSLRootCert    string
}

func NewPostgres(authOpts map[string]string, logLevel log.Level) (Postgres, error) {

	log.SetLevel(logLevel)

	//Set defaults for postgres

	pgOk := true
	missingOptions := ""

	log.Debugln("Initializing postgres backend with options:")

	for key, value := range authOpts {
		if strings.Contains(key, "pg_") {
			log.Debugf("%s: %s", key, value)
		}
	}

	var postgres = Postgres{
		Host:           "localhost",
		Port:           "5432",
		SSLMode:        "disable",
		SuperuserQuery: "",
		AclQuery:       "",
	}

	if host, ok := authOpts["pg_host"]; ok {
		postgres.Host = host
	}

	if port, ok := authOpts["pg_port"]; ok {
		postgres.Port = port
	}

	if dbName, ok := authOpts["pg_dbname"]; ok {
		postgres.DBName = dbName
	} else {
		pgOk = false
		missingOptions += " pg_dbname"
	}

	if user, ok := authOpts["pg_user"]; ok {
		postgres.User = user
	} else {
		pgOk = false
		missingOptions += " pg_user"
	}

	if password, ok := authOpts["pg_password"]; ok {
		postgres.Password = password
	} else {
		pgOk = false
		missingOptions += " pg_password"
	}

	if userQuery, ok := authOpts["pg_userquery"]; ok {
		postgres.UserQuery = userQuery
		log.Debugf("Postgres user query is: %s", userQuery)
	} else {
		pgOk = false
		missingOptions += " pg_userquery"
	}

	if superuserQuery, ok := authOpts["pg_superquery"]; ok {
		postgres.SuperuserQuery = superuserQuery
		log.Debugf("Postgres superuser query is: %s", superuserQuery)
	}

	if aclQuery, ok := authOpts["pg_aclquery"]; ok {
		postgres.AclQuery = aclQuery
		log.Debugf("Postgres acl query is: %s", aclQuery)
	}

	checkSSL := true

	if sslmode, ok := authOpts["pg_sslmode"]; ok {
		postgres.SSLMode = sslmode
	} else {
		postgres.SSLMode = "disable"
	}

	if sslCert, ok := authOpts["pg_sslcert"]; ok {
		postgres.SSLCert = sslCert
	} else {
		checkSSL = false
	}

	if sslKey, ok := authOpts["pg_sslkey"]; ok {
		postgres.SSLKey = sslKey
	} else {
		checkSSL = false
	}

	if sslCert, ok := authOpts["pg_sslrootcert"]; ok {
		postgres.SSLCert = sslCert
	} else {
		checkSSL = false
	}

	//Exit if any mandatory option is missing.
	if !pgOk {
		return postgres, errors.Errorf("PG backend error: missing options%s.\n", missingOptions)
	}

	//Build the dsn string and try to connect to the DB.
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s", postgres.User, postgres.Password, postgres.DBName, postgres.Host, postgres.Port)

	if (postgres.SSLMode == "verify-ca" || postgres.SSLMode == "verify-full") && checkSSL {
		connStr = fmt.Sprintf("%s sslmode=verify-ca sslcert=%s sslkey=%s sslrootcert=%s", connStr, postgres.SSLCert, postgres.SSLKey, postgres.SSLRootCert)
	} else if postgres.SSLMode == "required" {
		connStr = fmt.Sprintf("%s sslmode=require", connStr)
	} else {
		connStr = fmt.Sprintf("%s sslmode=disable", connStr)
	}

	var dbErr error
	postgres.DB, dbErr = common.OpenDatabase(connStr, "postgres")

	if dbErr != nil {
		return postgres, errors.Errorf("PG backend error: couldn't open DB: %s\n", dbErr)
	}

	return postgres, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Postgres) GetUser(username, password string) bool {

	var pwHash sql.NullString
	err := o.DB.Get(&pwHash, o.UserQuery, username)

	log.Debugf("Checking Postgres for user with username %s", username)
	log.WithFields(log.Fields{
		"query":    o.UserQuery,
		"username": username,
	}).Debug("sql query to be executed")

	if err != nil {
		log.Debugf("PG get user error: %s\n", err)
		return false
	}

	if !pwHash.Valid {
		log.Debugf("PG get user error: user %s not found.\n", username)
		return false
	}

	if common.HashCompare(password, pwHash.String) {
		return true
	}

	return false

}

//GetSuperuser checks that the username meets the superuser query.
func (o Postgres) GetSuperuser(username string) bool {

	//If there's no superuser query, return false.
	if o.SuperuserQuery == "" {
		return false
	}

	log.Debugf("Checking Postgres for superuser with username %s", username)

	log.WithFields(log.Fields{
		"query":    o.SuperuserQuery,
		"username": username,
	}).Debug("sql query to be executed")

	var count sql.NullInt64
	err := o.DB.Get(&count, o.SuperuserQuery, username)

	if err != nil {
		log.Debugf("PG get superuser error: %s\n", err)
		return false
	}

	if !count.Valid {
		log.Debugf("PG get superuser error: user %s not found.\n", username)
		return false
	}

	if count.Int64 > 0 {
		return true
	}

	return false

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Postgres) CheckAcl(username, topic, clientid string, acc int32) bool {

	//If there's no acl query, assume all privileges for all users.
	if o.AclQuery == "" {
		return true
	}

	log.Debugf("Checking Postgres for ACL for username %s, clientid %s, topic %s and access %d", username, clientid, topic, acc)

	log.WithFields(log.Fields{
		"query":    o.AclQuery,
		"username": username,
		"acc":      acc,
	}).Debug("sql query to be executed")

	var acls []string

	err := o.DB.Select(&acls, o.AclQuery, username, acc)

	if err != nil {
		log.Debugf("PG check acl error: %s\n", err)
		return false
	}

	for _, acl := range acls {
		aclTopic := strings.Replace(acl, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)
		if common.TopicsMatch(aclTopic, topic) {
			return true
		}
	}

	return false

}

//GetName returns the backend's name
func (o Postgres) GetName() string {
	return "Postgres"
}

//Halt closes the mysql connection.
func (o Postgres) Halt() {
	log.Debugln("Cleaning up Postgres backend")
	if o.DB != nil {
		err := o.DB.Close()
		if err != nil {
			log.Errorf("Postgres cleanup error: %s", err)
		}
	}
}
