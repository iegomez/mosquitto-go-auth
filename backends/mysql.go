package backends

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"

	mq "github.com/go-sql-driver/mysql"

	"github.com/iegomez/mosquitto-go-auth/common"
)

//Mysql holds all fields of the Mysql db connection.
type Mysql struct {
	DB                   *sqlx.DB
	Host                 string
	Port                 string
	DBName               string
	User                 string
	Password             string
	SaltEncoding         string
	UserQuery            string
	SuperuserQuery       string
	AclQuery             string
	SSLMode              string
	SSLCert              string
	SSLKey               string
	SSLRootCert          string
	Protocol             string
	SocketPath           string
	AllowNativePasswords bool
}

func NewMysql(authOpts map[string]string, logLevel log.Level) (Mysql, error) {

	log.SetLevel(logLevel)

	//Set defaults for Mysql

	mysqlOk := true
	missingOptions := ""

	var mysql = Mysql{
		Host:           "localhost",
		Port:           "3306",
		SSLMode:        "false",
		SuperuserQuery: "",
		AclQuery:       "",
		Protocol:       "tcp",
		SaltEncoding:	"base64",
	}

	if protocol, ok := authOpts["mysql_protocol"]; ok {
		mysql.Protocol = protocol
	}

	if socket, ok := authOpts["mysql_socket"]; ok {
		mysql.SocketPath = socket
	}

	if host, ok := authOpts["mysql_host"]; ok {
		mysql.Host = host
	}

	if port, ok := authOpts["mysql_port"]; ok {
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

	if saltEncoding, ok := authOpts["mysql_salt_encoding"]; ok {
		switch saltEncoding {
			case common.Base64, common.UTF8:
				mysql.SaltEncoding = saltEncoding
				log.Debugf("mysql backend: set salt encoding to: %s", saltEncoding)
			default:
				log.Errorf("mysql backend: invalid salt encoding specified: %s, will default to base64 instead", saltEncoding)
		}
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

	if allowNativePasswords, ok := authOpts["mysql_allow_native_passwords"]; ok && allowNativePasswords == "true" {
		mysql.AllowNativePasswords = true
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

	//If the protocol is a unix socket, we need to set the address as the socket path. If it's tcp, then set the address using host and port.
	addr := fmt.Sprintf("%s:%s", mysql.Host, mysql.Port)
	if mysql.Protocol == "unix" {
		if mysql.SocketPath != "" {
			addr = mysql.SocketPath
		} else {
			mysqlOk = false
			missingOptions += " mysql_socket"
		}
	}

	//Exit if any mandatory option is missing.
	if !mysqlOk {
		return mysql, errors.Errorf("MySql backend error: missing options: %s", missingOptions)
	}

	var msConfig = mq.Config{
		User:                 mysql.User,
		Passwd:               mysql.Password,
		Net:                  mysql.Protocol,
		Addr:                 addr,
		DBName:               mysql.DBName,
		TLSConfig:            mysql.SSLMode,
		AllowNativePasswords: mysql.AllowNativePasswords,
	}

	if customSSL {

		rootCertPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(mysql.SSLRootCert)
		if err != nil {
			return mysql, errors.Errorf("Mysql read root CA error: %s", err)
		}
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return mysql, errors.Errorf("Mysql failed to append root CA pem error: %s", err)
		}
		clientCert := make([]tls.Certificate, 0, 1)
		certs, err := tls.LoadX509KeyPair(mysql.SSLCert, mysql.SSLKey)
		if err != nil {
			return mysql, errors.Errorf("Mysql load key and cert error: %s", err)
		}
		clientCert = append(clientCert, certs)

		mq.RegisterTLSConfig("custom", &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: clientCert,
		})
	}

	var err error
	mysql.DB, err = common.OpenDatabase(msConfig.FormatDSN(), "mysql")

	if err != nil {
		return mysql, errors.Errorf("MySql backend error: couldn't open DB: %s", err)
	}

	return mysql, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Mysql) GetUser(username, password, clientid string) bool {

	var pwHash sql.NullString
	err := o.DB.Get(&pwHash, o.UserQuery, username)

	if err != nil {
		log.Debugf("MySql get user error: %s", err)
		return false
	}

	if !pwHash.Valid {
		log.Debugf("MySql get user error: user %s not found", username)
		return false
	}

	if common.HashCompare(password, pwHash.String, o.SaltEncoding) {
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
		log.Debugf("MySql get superuser error: %s", err)
		return false
	}

	if !count.Valid {
		log.Debugf("MySql get superuser error: user %s not found", username)
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
		log.Debugf("MySql check acl error: %s", err)
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

//Halt closes the mysql connection.
func (o Mysql) Halt() {
	if o.DB != nil {
		err := o.DB.Close()
		if err != nil {
			log.Errorf("Mysql cleanup error: %s", err)
		}
	}
}
