package backends

import (
	"database/sql"
	"strings"
	"context"
	
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type localJWTChecker struct {
	db        string
	postgres  Postgres
	mysql     Mysql
	mongo     Mongo
	userQuery string
	hasher    hashing.HashComparer
	options   tokenOptions
}

const (
	mysqlDB    = "mysql"
	postgresDB = "postgres"
	mongoDB = "mongo"
)

// NewLocalJWTChecker initializes a checker with a local DB.
func NewLocalJWTChecker(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer, options tokenOptions) (JWTChecker, error) {
	checker := &localJWTChecker{
		hasher:  hasher,
		db:      postgresDB,
		options: options,
	}

	missingOpts := ""
	localOk := true

	if options.secret == "" {
		return nil, errors.New("JWT backend error: missing JWT secret")
	}

	if db, ok := authOpts["JWT_db"]; ok {
		checker.db = db
	}

	if userQuery, ok := authOpts["JWT_userquery"]; ok {
		checker.userQuery = userQuery
	} else {
		localOk = false
		missingOpts += " JWT_userquery"
	}

	if !localOk {
		return nil, errors.Errorf("JWT backend error: missing local options: %s", missingOpts)
	}

	// Extract DB specific opts (e.g., host, port, etc.) to construct the underlying DB backend.
	dbAuthOpts := extractOpts(authOpts, checker.db)

	if checker.db == mysqlDB {
		mysql, err := NewMysql(dbAuthOpts, logLevel, hasher)
		if err != nil {
			return nil, errors.Errorf("JWT backend error: couldn't create mysql connector for local JWT: %s", err)
		}

		checker.mysql = mysql
	} else if checker.db == mongoDB {
		mongodb, err := NewMongo(dbAuthOpts, logLevel, hasher)

		if err != nil {
			return nil, errors.Errorf("JWT backend error: couldn't create mysql connector for local JWT: %s", err)
		}

		checker.mongo = mongodb
	} else {
		postgres, err := NewPostgres(dbAuthOpts, logLevel, hasher)

		checker.postgres = postgres
	}
	
	if err != nil {
		return nil, errors.Errorf("JWT backend error: couldn't create postgres connector for local JWT: %s", err)
	}

	return checker, nil
}

func (o *localJWTChecker) GetUser(token string) (bool, error) {
	username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

	if err != nil {
		log.Printf("JWT local get user error: %s", err)
		return false, err
	}

	return o.getLocalUser(username)
}

func (o *localJWTChecker) GetSuperuser(token string) (bool, error) {
	username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

	if err != nil {
		log.Printf("JWT local get superuser error: %s", err)
		return false, err
	}

	if o.db == mysqlDB {
		return o.mysql.GetSuperuser(username)
	} else if o.db == mongoDB {
		return o.mongo.GetSuperuser(username)
	} else {
		return o.postgres.GetSuperuser(username)
	}
}

func (o *localJWTChecker) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
	username, err := getUsernameForToken(o.options, token, o.options.skipACLExpiration)

	if err != nil {
		log.Printf("JWT local check acl error: %s", err)
		return false, err
	}

	if o.db == mysqlDB {
		return o.mysql.CheckAcl(username, topic, clientid, acc)
	} else if o.db == mongoDB {
		return o.mongo.CheckAcl(username)
	} else {
		return o.postgres.CheckAcl(username)
	}
}

func (o *localJWTChecker) Halt() {
	if o.postgres != (Postgres{}) && o.postgres.DB != nil {
		err := o.postgres.DB.Close()
	} else if o.mysql != (Mysql{}) && o.mysql.DB != nil {
		err := o.mysql.DB.Close()
	} else if o.mongo != (Mongo{}) && o.mongo.Conn != nil {
		err := o.mongo.Conn.Disconnect(context.TODO())
	}

	if err != nil {
		log.Errorf("JWT cleanup error: %s", err)
	}
}

func (o *localJWTChecker) getLocalUser(username string) (bool, error) {
	if o.userQuery == "" {
		return false, nil
	}

	var err error
	var sqlCount sql.NullInt64
	var count Int64
	var valid boolean
	
	if o.db == mysqlDB {
		err = o.mysql.DB.Get(&count, o.userQuery, username)
		valid = sqlCount.Valid
		count = sqlCount.Int64
	} else if o.db == mongoDB {
			var uc := o.mongo.Conn.Database(o.mongo.DBName).Collection(o.mongo.UsersCollection)
			
			count, err := uc.CountDocuments(context.TODO(), bson.M{"username": username})
	} else {
		err = o.postgres.DB.Get(&count, o.userQuery, username)
		valid = sqlCount.Valid
		count = sqlCount.Int64
	} 

	if err != nil {
		log.Debugf("local JWT get user error: %s", err)
		return false, err
	}

	if !valid {
		log.Debugf("local JWT get user error: user %s not found", username)
		return false, nil
	}

	if count > 0 {
		return true, nil
	}

	return false, nil
}

func extractOpts(authOpts map[string]string, db string) map[string]string {
	dbAuthOpts := make(map[string]string)

	if db == mysqlDB {
		dbPrefix = mysqlDB
	} else if db == mongoDB {
		dbPrefix = mongoDB
	} else {
		dbPrefix := "pg"
	}

	prefix := "JWT_" + dbPrefix

	for k, v := range authOpts {
		if strings.HasPrefix(k, prefix) {
			dbAuthOpts[strings.TrimPrefix(k, "JWT_")] = v
		}
	}

	// Set a dummy query for user check since it won't be checked with the DB backend's method.
	dbAuthOpts[dbPrefix+"_userquery"] = "dummy"

	return dbAuthOpts
}
