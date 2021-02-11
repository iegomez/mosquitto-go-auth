package backends

import (
	"database/sql"
	"strings"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type localJWTChecker struct {
	db        string
	postgres  Postgres
	mysql     Mysql
	userQuery string
	hasher    hashing.HashComparer
	options   tokenOptions
}

const (
	mysqlDB    = "mysql"
	postgresDB = "postgres"
)

// NewLocalJWTChecker initializes a checker with a local DB.
func NewLocalJWTChecker(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer, options tokenOptions) (jwtChecker, error) {
	checker := &localJWTChecker{
		hasher:  hasher,
		db:      postgresDB,
		options: options,
	}

	missingOpts := ""
	localOk := true

	if options.secret == "" {
		return nil, errors.New("JWT backend error: missing jwt secret")
	}

	if db, ok := authOpts["jwt_db"]; ok {
		checker.db = db
	}

	if userQuery, ok := authOpts["jwt_userquery"]; ok {
		checker.userQuery = userQuery
	} else {
		localOk = false
		missingOpts += " jwt_userquery"
	}

	if !localOk {
		return nil, errors.Errorf("JWT backend error: missing local options: %s", missingOpts)
	}

	// Extract DB specific opts (e.g., host, port, etc.) to construct the underlying DB backend.
	dbAuthOpts := extractOpts(authOpts, checker.db)

	if checker.db == mysqlDB {
		mysql, err := NewMysql(dbAuthOpts, logLevel, hasher)
		if err != nil {
			return nil, errors.Errorf("JWT backend error: couldn't create mysql connector for local jwt: %s", err)
		}

		checker.mysql = mysql

		return checker, nil
	}

	postgres, err := NewPostgres(dbAuthOpts, logLevel, hasher)
	if err != nil {
		return nil, errors.Errorf("JWT backend error: couldn't create postgres connector for local jwt: %s", err)
	}

	checker.postgres = postgres

	return checker, nil
}

func (o *localJWTChecker) GetUser(token string) (bool, error) {
	username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

	if err != nil {
		log.Printf("jwt local get user error: %s", err)
		return false, err
	}

	return o.getLocalUser(username)
}

func (o *localJWTChecker) GetSuperuser(token string) (bool, error) {
	username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

	if err != nil {
		log.Printf("jwt local get superuser error: %s", err)
		return false, err
	}

	if o.db == mysqlDB {
		return o.mysql.GetSuperuser(username)
	}

	return o.postgres.GetSuperuser(username)
}

func (o *localJWTChecker) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
	username, err := getUsernameForToken(o.options, token, o.options.skipACLExpiration)

	if err != nil {
		log.Printf("jwt local check acl error: %s", err)
		return false, err
	}

	if o.db == mysqlDB {
		return o.mysql.CheckAcl(username, topic, clientid, acc)
	}

	return o.postgres.CheckAcl(username, topic, clientid, acc)
}

func (o *localJWTChecker) Halt() {
	if o.postgres != (Postgres{}) && o.postgres.DB != nil {
		err := o.postgres.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	} else if o.mysql != (Mysql{}) && o.mysql.DB != nil {
		err := o.mysql.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	}
}

func (o *localJWTChecker) getLocalUser(username string) (bool, error) {
	if o.userQuery == "" {
		return false, nil
	}

	var count sql.NullInt64
	var err error
	if o.db == mysqlDB {
		err = o.mysql.DB.Get(&count, o.userQuery, username)
	} else {
		err = o.postgres.DB.Get(&count, o.userQuery, username)
	}

	if err != nil {
		log.Debugf("local JWT get user error: %s", err)
		return false, err
	}

	if !count.Valid {
		log.Debugf("local JWT get user error: user %s not found", username)
		return false, nil
	}

	if count.Int64 > 0 {
		return true, nil
	}

	return false, nil
}

func extractOpts(authOpts map[string]string, db string) map[string]string {
	dbAuthOpts := make(map[string]string)

	dbPrefix := "pg"
	if db == mysqlDB {
		dbPrefix = mysqlDB
	}

	prefix := "jwt_" + dbPrefix

	for k, v := range authOpts {
		if strings.HasPrefix(k, prefix) {
			dbAuthOpts[strings.TrimPrefix(k, "jwt_")] = v
		}
	}

	// Set a dummy query for user check since it won't be checked with the DB backend's method.
	dbAuthOpts[dbPrefix+"_userquery"] = "dummy"

	return dbAuthOpts
}
