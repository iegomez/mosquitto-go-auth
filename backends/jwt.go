package backends

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"

	jwt "github.com/dgrijalva/jwt-go"
)

type JWT struct {
	Remote  bool
	LocalDB string

	Postgres       Postgres
	Mysql          Mysql
	Secret         string
	UserQuery      string
	SuperuserQuery string
	AclQuery       string

	UserUri      string
	SuperuserUri string
	AclUri       string
	Host         string
	Port         string
	WithTLS      bool
	VerifyPeer   bool

	ParamsMode   string
	ResponseMode string
}

// Claims defines the struct containing the token claims. Subject should contain the username.
type Claims struct {
	jwt.StandardClaims
}

type Response struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewJWT(authOpts map[string]string, logLevel log.Level) (JWT, error) {

	log.SetLevel(logLevel)

	//Initialize with defaults
	var jwt = JWT{
		Remote:       false,
		WithTLS:      false,
		VerifyPeer:   false,
		ResponseMode: "status",
		ParamsMode:   "json",
		LocalDB:      "postgres",
	}

	if remote, ok := authOpts["jwt_remote"]; ok && remote == "true" {
		jwt.Remote = true
	}

	//If remote, set remote api fields. Else, set jwt secret.

	if jwt.Remote {

		missingOpts := ""
		remoteOk := true

		if responseMode, ok := authOpts["jwt_response_mode"]; ok {
			if responseMode == "text" || responseMode == "json" {
				jwt.ResponseMode = responseMode
			}
		}

		if paramsMode, ok := authOpts["jwt_params_mode"]; ok {
			if paramsMode == "form" {
				jwt.ParamsMode = paramsMode
			}
		}

		if userUri, ok := authOpts["jwt_getuser_uri"]; ok {
			jwt.UserUri = userUri
		} else {
			remoteOk = false
			missingOpts += " jwt_getuser_uri"
		}

		if superuserUri, ok := authOpts["jwt_superuser_uri"]; ok {
			jwt.SuperuserUri = superuserUri
		} else {
			remoteOk = false
			missingOpts += " jwt_superuser_uri"
		}

		if aclUri, ok := authOpts["jwt_aclcheck_uri"]; ok {
			jwt.AclUri = aclUri
		} else {
			remoteOk = false
			missingOpts += " jwt_aclcheck_uri"
		}

		if hostname, ok := authOpts["jwt_host"]; ok {
			jwt.Host = hostname
		} else {
			remoteOk = false
			missingOpts += " jwt_host"
		}

		if port, ok := authOpts["jwt_port"]; ok {
			jwt.Port = port
		} else {
			remoteOk = false
			missingOpts += " jwt_port"
		}

		if withTLS, ok := authOpts["jwt_with_tls"]; ok && withTLS == "true" {
			jwt.WithTLS = true
		}

		if verifyPeer, ok := authOpts["jwt_verify_peer"]; ok && verifyPeer == "true" {
			jwt.VerifyPeer = true
		}

		if !remoteOk {
			return jwt, errors.Errorf("JWT backend error: missing remote options%s.\n", missingOpts)
		}

	} else {

		missingOpts := ""
		localOk := true

		if secret, ok := authOpts["jwt_secret"]; ok {
			jwt.Secret = secret
		} else {
			return jwt, errors.New("JWT backend error: missing jwt secret.\n")
		}

		if userQuery, ok := authOpts["jwt_userquery"]; ok {
			jwt.UserQuery = userQuery
		} else {
			localOk = false
			missingOpts += " jwt_userquery"
		}

		if superuserQuery, ok := authOpts["jwt_superquery"]; ok {
			jwt.SuperuserQuery = superuserQuery
		}

		if aclQuery, ok := authOpts["jwt_aclquery"]; ok {
			jwt.AclQuery = aclQuery
		}

		if localDB, ok := authOpts["jwt_db"]; ok {
			jwt.LocalDB = localDB
		}

		if !localOk {
			return jwt, errors.Errorf("JWT backend error: missing local options%s.\n", missingOpts)
		}

		if jwt.LocalDB == "mysql" {
			//Try to create a mysql backend with these custom queries
			mysql, err := NewMysql(authOpts, logLevel)
			if err != nil {
				return jwt, errors.Errorf("JWT backend error: couldn't create mysql connector for local jwt: %s\n", err)
			}
			mysql.UserQuery = jwt.UserQuery
			mysql.SuperuserQuery = jwt.SuperuserQuery
			mysql.AclQuery = jwt.AclQuery

			jwt.Mysql = mysql
		} else {
			//Try to create a postgres backend with these custom queries.
			postgres, err := NewPostgres(authOpts, logLevel)
			if err != nil {
				return jwt, errors.Errorf("JWT backend error: couldn't create postgres connector for local jwt: %s\n", err)
			}
			postgres.UserQuery = jwt.UserQuery
			postgres.SuperuserQuery = jwt.SuperuserQuery
			postgres.AclQuery = jwt.AclQuery

			jwt.Postgres = postgres
		}

	}

	return jwt, nil
}

func (o JWT) GetUser(token, password string) bool {

	if o.Remote {
		var dataMap map[string]interface{}
		var urlValues = url.Values{}
		return jwtRequest(o.Host, o.UserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	//If not remote, get the claims and check against postgres for user.
	claims, err := o.getClaims(token)

	if err != nil {
		log.Printf("jwt get user error: %s\n", err)
		return false
	}
	//Now check against the DB.
	return o.getLocalUser(claims.Subject)

}

func (o JWT) GetSuperuser(token string) bool {

	if o.Remote {
		var dataMap map[string]interface{}
		var urlValues = url.Values{}
		return jwtRequest(o.Host, o.SuperuserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	//If not remote, get the claims and check against postgres for user.
	//But check first that there's superuser query.
	if o.SuperuserQuery == "" {
		return false
	}
	claims, err := o.getClaims(token)

	if err != nil {
		log.Debugf("jwt get superuser error: %s\n", err)
		return false
	}
	//Now check against DB
	if o.LocalDB == "mysql" {
		return o.Mysql.GetSuperuser(claims.Subject)
	} else {
		return o.Postgres.GetSuperuser(claims.Subject)
	}

}

func (o JWT) CheckAcl(token, topic, clientid string, acc int32) bool {

	if o.Remote {
		dataMap := map[string]interface{}{
			"clientid": clientid,
			"topic":    topic,
			"acc":      acc,
		}
		var urlValues = url.Values{
			"clientid": []string{clientid},
			"topic":    []string{topic},
			"acc":      []string{strconv.Itoa(int(acc))},
		}
		return jwtRequest(o.Host, o.AclUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	//If not remote, get the claims and check against postgres for user.
	//But check first that there's acl query.
	if o.AclQuery == "" {
		return true
	}
	claims, err := o.getClaims(token)

	if err != nil {
		log.Debugf("jwt check acl error: %s\n", err)
		return false
	}
	//Now check against the DB.
	if o.LocalDB == "mysql" {
		return o.Mysql.CheckAcl(claims.Subject, topic, clientid, acc)
	} else {
		return o.Postgres.CheckAcl(claims.Subject, topic, clientid, acc)
	}

}

func jwtRequest(host, uri, token string, withTLS, verifyPeer bool, dataMap map[string]interface{}, port, paramsMode, responseMode string, urlValues url.Values) bool {

	tlsStr := "http://"

	if withTLS {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s%s", tlsStr, host, uri)
	if port != "" {
		fullUri = fmt.Sprintf("%s%s:%s%s", tlsStr, host, port, uri)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	var resp *http.Response
	var err error

	if !verifyPeer {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}

	var req *http.Request
	var reqErr error

	if paramsMode == "json" {
		dataJson, mErr := json.Marshal(dataMap)

		if mErr != nil {
			log.Errorf("marshal error: %v\n", mErr)
			return false
		}

		contentReader := bytes.NewReader(dataJson)
		req, reqErr = http.NewRequest("POST", fullUri, contentReader)

		if reqErr != nil {
			log.Errorf("req error: %v\n", reqErr)
			return false
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, reqErr = http.NewRequest("POST", fullUri, strings.NewReader(urlValues.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(urlValues.Encode())))

		if reqErr != nil {
			log.Errorf("req error: %v\n", reqErr)
			return false
		}
	}

	req.Header.Set("authorization", token)

	resp, err = client.Do(req)

	if err != nil {
		log.Errorf("error: %v\n", err)
		return false
	}

	body, bErr := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if bErr != nil {
		log.Errorf("read error: %v\n", bErr)
		return false
	}

	if resp.Status != "200 OK" {
		log.Infof("error code: %v\n", err)
		return false
	}

	if responseMode == "text" {

		//For test response, we expect "ok" or an error message.
		if string(body) != "ok" {
			log.Infof("api error: %s\n", string(body))
			return false
		}

	} else if responseMode == "json" {

		//For json response, we expect Ok and Error fields.
		response := Response{Ok: false, Error: ""}
		jErr := json.Unmarshal(body, &response)

		if jErr != nil {
			log.Errorf("unmarshal error: %v\n", jErr)
			return false
		}

		if !response.Ok {
			log.Infof("api error: %s\n", response.Error)
			return false
		}

	}

	log.Debugf("jwt request approved for %s\n", token)
	return true

}

//GetName returns the backend's name
func (o JWT) GetName() string {
	return "JWT"
}

func (o JWT) getLocalUser(username string) bool {
	//If there's no user query, return false.
	if o.UserQuery == "" {
		return false
	}

	var count sql.NullInt64
	var err error
	if o.LocalDB == "mysql" {
		err = o.Mysql.DB.Get(&count, o.UserQuery, username)
	} else {
		err = o.Postgres.DB.Get(&count, o.UserQuery, username)
	}

	if err != nil {
		log.Debugf("Local JWT get user error: %s\n", err)
		return false
	}

	if !count.Valid {
		log.Debugf("Local JWT get user error: user %s not found.\n", username)
		return false
	}

	if count.Int64 > 0 {
		return true
	}

	return false
}

func (o JWT) getClaims(tokenStr string) (*Claims, error) {

	jwtToken, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(o.Secret), nil
	})

	if err != nil {
		log.Debugf("jwt parse error: %s\n", err)
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, errors.New("jwt invalid token")
	}

	claims, ok := jwtToken.Claims.(*Claims)
	if !ok {
		// no need to use a static error, this should never happen
		log.Debugf("api/auth: expected *Claims, got %T", jwtToken.Claims)
		return nil, errors.New("got strange claims")
	}

	return claims, nil
}

//Halt closes any DB connection.
func (o JWT) Halt() {
	if o.Postgres != (Postgres{}) && o.Postgres.DB != nil {
		err := o.Postgres.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	} else if o.Mysql != (Mysql{}) && o.Mysql.DB != nil {
		err := o.Mysql.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	}
}
