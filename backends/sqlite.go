package backends

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//Sqlite holds all fields of the sqlite db connection.
type Sqlite struct {
	DB             *sqlx.DB
	Source         string
	UserQuery      string
	SuperuserQuery string
	AclQuery       string
	hasher         hashing.HashComparer

	connectTries int
}

func NewSqlite(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (Sqlite, error) {

	log.SetLevel(logLevel)

	//Set defaults for sqlite

	sqliteOk := true
	missingOptions := ""

	var sqlite = Sqlite{
		SuperuserQuery: "",
		AclQuery:       "",
		hasher:         hasher,
	}

	if source, ok := authOpts["sqlite_source"]; ok {
		sqlite.Source = source
	} else {
		sqliteOk = false
		missingOptions += " sqlite_source"
	}

	if userQuery, ok := authOpts["sqlite_userquery"]; ok {
		sqlite.UserQuery = userQuery
	} else {
		sqliteOk = false
		missingOptions += " sqlite_userquery"
	}

	if superuserQuery, ok := authOpts["sqlite_superquery"]; ok {
		sqlite.SuperuserQuery = superuserQuery
	}

	if aclQuery, ok := authOpts["sqlite_aclquery"]; ok {
		sqlite.AclQuery = aclQuery
	}

	//Exit if any mandatory option is missing.
	if !sqliteOk {
		return sqlite, errors.Errorf("sqlite backend error: missing options: %s", missingOptions)
	}

	//Build the dsn string and try to connect to the db.
	connStr := ":memory:"
	if sqlite.Source != "memory" {
		connStr = sqlite.Source
	}

	if tries, ok := authOpts["sqlite_connect_tries"]; ok {
		connectTries, err := strconv.Atoi(tries)

		if err != nil {
			log.Warnf("invalid sqlite connect tries options: %s", err)
		} else {
			sqlite.connectTries = connectTries
		}
	}

	var err error
	sqlite.DB, err = OpenDatabase(connStr, "sqlite3", sqlite.connectTries)

	if err != nil {
		return sqlite, errors.Errorf("sqlite backend error: couldn't open db %s: %s", connStr, err)
	}

	return sqlite, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Sqlite) GetUser(username, password, clientid string) bool {

	var pwHash sql.NullString
	err := o.DB.Get(&pwHash, o.UserQuery, username)

	if err != nil {
		log.Debugf("SQlite get user error: %s", err)
		return false
	}

	if !pwHash.Valid {
		log.Debugf("SQlite get user error: user %s not found.", username)
		return false
	}

	if o.hasher.Compare(password, pwHash.String) {
		return true
	}

	return false

}

//GetSuperuser checks that the username meets the superuser query.
func (o Sqlite) GetSuperuser(username string) bool {

	//If there's no superuser query, return false.
	if o.SuperuserQuery == "" {
		return false
	}

	var count sql.NullInt64
	err := o.DB.Get(&count, o.SuperuserQuery, username)

	if err != nil {
		log.Debugf("sqlite get superuser error: %s", err)
		return false
	}

	if !count.Valid {
		log.Debugf("sqlite get superuser error: user %s not found", username)
		return false
	}

	if count.Int64 > 0 {
		return true
	}

	return false

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Sqlite) CheckAcl(username, topic, clientid string, acc int32) bool {
	//If there's no acl query, assume all privileges for all users.
	if o.AclQuery == "" {
		return true
	}

	var acls []string

	err := o.DB.Select(&acls, o.AclQuery, username, acc)

	if err != nil {
		log.Debugf("sqlite check acl error: %s", err)
		return false
	}

	for _, acl := range acls {
		aclTopic := strings.Replace(acl, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)
		if TopicsMatch(aclTopic, topic) {
			return true
		}
	}

	return false

}

//GetName returns the backend's name
func (o Sqlite) GetName() string {
	return "Sqlite"
}

//Halt closes the mysql connection.
func (o Sqlite) Halt() {
	if o.DB != nil {
		err := o.DB.Close()
		if err != nil {
			log.Errorf("sqlite cleanup error: %s", err)
		}
	}
}
