package backends

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"

	mq "github.com/go-sql-driver/mysql"

	"github.com/iegomez/mosquitto-go-auth/common"
)

//Mysql holds all fields of the Mysql db connection.
type Mysql struct {
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
	Protocol       string
	SocketPath     string
}

func NewMysql(authOpts map[string]string) (Mysql, error) {

	//Set defaults for Mysql

	mysqlOk := true
	missingOptions := ""

	var mysql = Mysql{
		Host:           "localhost",
		Port:           "3306",
		SSLMode:        "false",
		SuperuserQuery: "",
		AclQuery:       "",
	}

	if host, ok := authOpts["mysql_host"]; ok {
		mysql.Host = host
	}

	if port, ok := authOpts["mysqlport"]; ok {
		mysql.Port = port
	}

	if dbName, ok := authOpts["mysql_dbname"]; ok {
		mysql.DBName = dbName
	} else {
		mysqlOk = false
		missingOptions += " mysql_dbname"
	}

	if user, ok := authOpts["mysql_user"]; ok {
		mysql.User = user
	} else {
		mysqlOk = false
		missingOptions += " mysql_user"
	}

	if password, ok := authOpts["mysql_password"]; ok {
		mysql.Password = password
	} else {
		mysqlOk = false
		missingOptions += " mysql_password"
	}

	if userQuery, ok := authOpts["mysql_userquery"]; ok {
		mysql.UserQuery = userQuery
	} else {
		mysqlOk = false
		missingOptions += " mysql_userquery"
	}

	if superuserQuery, ok := authOpts["mysql_superquery"]; ok {
		mysql.SuperuserQuery = superuserQuery
	}

	if aclQuery, ok := authOpts["mysql_aclquery"]; ok {
		mysql.AclQuery = aclQuery
	}

	customSSL := false

	if sslmode, ok := authOpts["mysql_sslmode"]; ok {
		if sslmode == "custom" {
			customSSL = true
		}
		mysql.SSLMode = sslmode
	}

	if sslCert, ok := authOpts["mysql_sslcert"]; ok {
		mysql.SSLCert = sslCert
	} else {
		customSSL = false
	}

	if sslKey, ok := authOpts["mysql_sslkey"]; ok {
		mysql.SSLKey = sslKey
	} else {
		customSSL = false
	}

	if sslCert, ok := authOpts["mysql_sslrootcert"]; ok {
		mysql.SSLCert = sslCert
	} else {
		customSSL = false
	}

	//Exit if any mandatory option is missing.
	if !mysqlOk {
		return mysql, errors.Errorf("MySql backend error: missing options%s.\n", missingOptions)
	}

	var msConfig = mq.Config{
		User:      mysql.User,
		Passwd:    mysql.Password,
		Net:       mysql.Protocol,
		Addr:      fmt.Sprintf("%s:%s", mysql.Host, mysql.Port),
		DBName:    mysql.DBName,
		TLSConfig: mysql.SSLMode,
	}

	if customSSL {

		rootCertPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(mysql.SSLRootCert)
		if err != nil {
			return mysql, errors.Errorf("Mysql read root CA error: %s\n", err)
		}
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return mysql, errors.Errorf("Mysql failed to append root CA pem error: %s\n", err)
		}
		clientCert := make([]tls.Certificate, 0, 1)
		certs, err := tls.LoadX509KeyPair(mysql.SSLCert, mysql.SSLKey)
		if err != nil {
			return mysql, errors.Errorf("Mysql load key and cert error: %s\n", err)
		}
		clientCert = append(clientCert, certs)

		mq.RegisterTLSConfig("custom", &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: clientCert,
		})
	}

	var dbErr error
	mysql.DB, dbErr = common.OpenDatabase(msConfig.FormatDSN(), "mysql")

	if dbErr != nil {
		return mysql, errors.Errorf("MySql backend error: couldn't open DB: %s\n", dbErr)
	}

	log.Println("Connected to mysql DB.")

	return mysql, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Mysql) GetUser(username, password string) bool {

	var pwHash sql.NullString
	err := o.DB.Get(&pwHash, o.UserQuery, username)

	if err != nil {
		log.Printf("MySql get user error: %s\n", err)
		return false
	}

	if !pwHash.Valid {
		log.Printf("MySql get user error: user %s not found.\n", username)
		return false
	}

	if common.HashCompare(password, pwHash.String) {
		return true
	}

	return false

}

//GetSuperuser checks that the username meets the superuser query.
func (o Mysql) GetSuperuser(username string) bool {

	//If there's no superuser query, return false.
	if o.SuperuserQuery == "" {
		return false
	}

	var count sql.NullInt64
	err := o.DB.Get(&count, o.SuperuserQuery, username)

	if err != nil {
		log.Printf("MySql get superuser error: %s\n", err)
		return false
	}

	if !count.Valid {
		log.Printf("MySql get superuser error: user %s not found.\n", username)
		return false
	}

	if count.Int64 > 0 {
		return true
	}

	return false

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Mysql) CheckAcl(username, topic, clientid string, acc int32) bool {
	//If there's no acl query, assume all privileges for all users.
	if o.AclQuery == "" {
		return true
	}

	var acls []string

	err := o.DB.Select(&acls, o.AclQuery, username, acc)

	if err != nil {
		log.Printf("MySql check acl error: %s\n", err)
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
func (o Mysql) GetName() string {
	return "Mysql"
}
