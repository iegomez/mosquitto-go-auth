package backends

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	h "net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	jwt_go "github.com/dgrijalva/jwt-go"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type JWT struct {
	Remote  bool
	LocalDB string

	Postgres       Postgres
	Mysql          Mysql
	Secret         interface{}
	UserQuery      string
	SuperuserQuery string
	AclQuery       string
	AclScopeField  string

	UserUri      string
	SuperuserUri string
	AclUri       string
	Host         string
	Port         string
	WithTLS      bool
	VerifyPeer   bool

	ParamsMode   string
	ResponseMode string

	UserField string

	Client *h.Client

	hasher hashing.HashComparer
}

// Claims defines the struct containing the token claims. StandardClaim's Subject field should contain the username, unless an opt is set to support Username field.
type Claims struct {
	jwt_go.StandardClaims
	// If set, Username defines the identity of the user.
	Username string `json:"username"`
}

type Response struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewJWT(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (JWT, error) {

	log.SetLevel(logLevel)

	//Initialize with defaults
	var jwt = JWT{
		Remote:       false,
		WithTLS:      false,
		VerifyPeer:   false,
		ResponseMode: "status",
		ParamsMode:   "json",
		LocalDB:      "postgres",
		UserField:    "Subject",
		hasher:       hasher,
	}

	if userField, ok := authOpts["jwt_userfield"]; ok && userField == "Username" {
		jwt.UserField = userField
	} else {
		log.Debugln("JWT user field not present or incorrect, defaulting to Subject field.")
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
			return jwt, errors.Errorf("JWT backend error: missing remote options: %s", missingOpts)
		}

		jwt.Client = &h.Client{Timeout: 5 * time.Second}

		if !jwt.VerifyPeer {
			tr := &h.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			jwt.Client.Transport = tr
		}

	} else {

		missingOpts := ""
		localOk := true

		if secret, ok := authOpts["jwt_secret"]; ok {
			jwt.Secret = []byte(secret)
		} else if pub_key_file, ok := authOpts["jwt_public_key_file"]; ok {
			verifyBytes, err := ioutil.ReadFile(pub_key_file)
			if err != nil {
				return jwt, errors.Errorf("JWT backend error: couldn't read public key file for local jwt: %s", err)
			}
			// @todo auto-select PEM-type?
			secretObj, err := jwt_go.ParseRSAPublicKeyFromPEM(verifyBytes)
			if err != nil {
				return jwt, errors.Errorf("JWT backend error: couldn't parse public key file for local jwt: %s", err)
			}
			jwt.Secret = secretObj
		} else {
			return jwt, errors.New("JWT backend error: missing jwt secret")
		}

		if localDB, ok := authOpts["jwt_db"]; ok {
			jwt.LocalDB = localDB
		}

		// If no localDB, just verify the claims with the public key, so no queries are needed
		if jwt.LocalDB != "none" {
			if userQuery, ok := authOpts["jwt_userquery"]; ok {
				jwt.UserQuery = userQuery
			} else {
				localOk = false
				missingOpts += " jwt_userquery"
			}

			if superuserQuery, ok := authOpts["jwt_superquery"]; ok {
				jwt.SuperuserQuery = superuserQuery
			}
		}

		if aclQuery, ok := authOpts["jwt_aclquery"]; ok {
			jwt.AclQuery = aclQuery
		}
		if aclScopeField, ok := authOpts["jwt_acl_scope_field"]; ok {
			jwt.AclScopeField = aclScopeField
		}

		if !localOk {
			return jwt, errors.Errorf("JWT backend error: missing local options: %s", missingOpts)
		}

		if jwt.LocalDB == "mysql" {
			//Try to create a mysql backend with these custom queries
			mysql, err := NewMysql(authOpts, logLevel, hasher)
			if err != nil {
				return jwt, errors.Errorf("JWT backend error: couldn't create mysql connector for local jwt: %s", err)
			}
			mysql.UserQuery = jwt.UserQuery
			mysql.SuperuserQuery = jwt.SuperuserQuery
			mysql.AclQuery = jwt.AclQuery

			jwt.Mysql = mysql
		} else if jwt.LocalDB == "postgres" {
			//Try to create a postgres backend with these custom queries.
			postgres, err := NewPostgres(authOpts, logLevel, hasher)
			if err != nil {
				return jwt, errors.Errorf("JWT backend error: couldn't create postgres connector for local jwt: %s", err)
			}
			postgres.UserQuery = jwt.UserQuery
			postgres.SuperuserQuery = jwt.SuperuserQuery
			postgres.AclQuery = jwt.AclQuery

			jwt.Postgres = postgres
		}

	}

	return jwt, nil
}

//GetUser authenticates a given user.
func (o JWT) GetUser(token, password, clientid string) bool {

	if o.Remote {
		var dataMap map[string]interface{}
		var urlValues = url.Values{}
		return o.jwtRequest(o.Host, o.UserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	// If not remote, get and verify the claims
	claims, err := o.getClaims(token)

	if err != nil {
		log.Printf("jwt get user error: %s", err)
		return false
	}

	// If no database is set, just verifying the claim is fine.
	if o.LocalDB == "none" {
		return true
	}

	// If localDB is set, check against database for user.
	//Now check against the db.
	if o.UserField == "Username" {
		return o.getLocalUser(claims.Username)
	}
	return o.getLocalUser(claims.Subject)

}

//GetSuperuser checks if the given user is a superuser.
func (o JWT) GetSuperuser(token string) bool {
	if o.Remote {
		if o.SuperuserUri == "" {
			return false
		}
		var dataMap map[string]interface{}
		var urlValues = url.Values{}
		return o.jwtRequest(o.Host, o.SuperuserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	//If not remote, get the claims and check against postgres for user.
	//But check first that there's superuser query.
	if o.SuperuserQuery == "" {
		return false
	}
	claims, err := o.getClaims(token)

	if err != nil {
		log.Debugf("jwt get superuser error: %s", err)
		return false
	}
	//Now check against db
	if o.UserField == "Username" {
		if o.LocalDB == "mysql" {
			return o.Mysql.GetSuperuser(claims.Username)
		} else if o.LocalDB == "postgres" {
			return o.Postgres.GetSuperuser(claims.Username)
		}
	}

	if o.LocalDB == "mysql" {
		return o.Mysql.GetSuperuser(claims.Subject)
	} else if o.LocalDB == "postgres" {
		return o.Postgres.GetSuperuser(claims.Subject)
	}
	return false
}

// Check acl in a db-less context. AclQuery contains a comma separated string with expressions. Each expression consists
// of a string to match with, then a column (:), then a regex to match against. Both string and regex can have placeholders.
// The placeholders in the form %fieldname% are substituted first with as values the fields from the claims (short, lowercase
// variants, as they are in json). Additionally, %clientId%, %topic%, %access% and %scope% can be used. %access% is the
// requested access as string, so either read, write or subscribe. If access is readwrite, the test is done for write and
// read apart and AND'd. %scope% is taken from the claims, the field is set in config AclScopeField. It is then spit on spaces
// and for each %scope% is filled and the expression is evaluated. On the first match access is granted (so OR'd). If no scope
// is given, ["default"] is used.
// Example:
//	 auth_opt_jwt_aclquery %scope% %access% %topic%:read-scope read topic/%sub%,%scope% %access% %topic%:test-scope (read|write|subscribe) other/%clientId%/%sub%
//	 auth_opt_jwt_acl_scope_field scope
func (o JWT) checkAclLocal(tokenStr, topic, clientId string, acc int32) bool {
	// no query, return true
	if o.AclQuery == "" {
		return true
	}

	parser := &jwt_go.Parser{
		SkipClaimsValidation: true,
	}
	jwtToken, err := parser.Parse(tokenStr, func(token *jwt_go.Token) (interface{}, error) {
		return o.Secret, nil
	})
	if err != nil {
		log.Debugf("jwt parse error: %s", err)
		return false
	}

	claims, ok := jwtToken.Claims.(jwt_go.MapClaims)
	if !ok {
		// no need to use a static error, this should never happen
		log.Debugf("api/auth: expected *jwt_go.MapClaims, got %T", jwtToken.Claims)
		return false
	}

	// prepare values-map
	values := map[string]interface{}{}
	for k, v := range claims {
		values[k] = v
	}
	// Add other static vars
	values["topic"] = topic
	values["clientId"] = clientId

	// Iterate all scopes. If one scope matches, return true.
	// Do so for the requested access. For access readwrite, we do the read and write separately and AND the result.
	for _, scope := range o.getScopes(&claims) {
		values["scope"] = scope
		match := false
		switch acc {
		case MOSQ_ACL_READ:
			values["access"] = "read"
			match = evalAclQuery(o.AclQuery, &values)
		case MOSQ_ACL_WRITE:
			values["access"] = "write"
			match = evalAclQuery(o.AclQuery, &values)
		case MOSQ_ACL_READWRITE:
			// Do AND of write and read
			values["access"] = "write"
			match = evalAclQuery(o.AclQuery, &values)
			if match {
				values["access"] = "read"
				match = evalAclQuery(o.AclQuery, &values)
			}
		case MOSQ_ACL_SUBSCRIBE:
			values["access"] = "subscribe"
			match = evalAclQuery(o.AclQuery, &values)
		}
		if match {
			return true
		}
	}
	return false
}

// If AclScopeField is set, get that field from claims. Split it on whitespace and return as string-slice.
// If none set, or anything goes wrong, return ["default"]
func (o JWT) getScopes(claims *jwt_go.MapClaims) []string {
	if o.AclScopeField != "" {
		scopes, ok := (*claims)[o.AclScopeField]
		if ok {
			scopesStr, ok := scopes.(string)
			if ok {
				return strings.Fields(scopesStr)
			}
		}
	}
	return []string{"default"}
}

// Replace placeholders and eval query
func evalAclQuery(query string, valuesPtr *map[string]interface{}) bool {
	acl := replacePlaceholders(query, valuesPtr)

	for _, rule := range strings.Split(acl, ",") {
		parts := strings.SplitN(rule, ":", 2)
		log.Debugf("Match %s against %s", parts[0], parts[1])

		aclReg, err := regexp.Compile(parts[1])
		if err != nil {
			log.Errorf("Regexp compile %s failed %s", acl, err)
			continue
		}

		if aclReg.MatchString(parts[0]) {
			return true
		}
	}
	return false
}

// Replace placeholders
func replacePlaceholders(subject string, valuesPtr *map[string]interface{}) string {
	reg, err := regexp.Compile(`%\w+%`)
	if err != nil {
		log.Errorf("Regexp compile %s failed %s", `%\w+%`, err)
		return subject
	}

	return reg.ReplaceAllStringFunc(subject, func(s string) string {
		f := s[1 : len(s)-1]
		v, ok := (*valuesPtr)[f]
		if ok {
			switch v := v.(type) {
			case bool:
				strconv.FormatBool(bool(v))
			case float64:
				return strconv.FormatFloat(float64(v), 'f', 1, 64)
			case int64:
				return strconv.Itoa(int(v))
			case string:
				return string(v)
			}
		}
		return ""
	})
}

//CheckAcl checks user authorization.
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
		return o.jwtRequest(o.Host, o.AclUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}
	if o.LocalDB == "none" {
		return o.checkAclLocal(token, topic, clientid, acc)
	}

	//If not remote, get the claims and check against postgres for user.
	//But check first that there's acl query.
	if o.AclQuery == "" {
		return true
	}
	claims, err := o.getClaims(token)

	if err != nil {
		log.Debugf("jwt check acl error: %s", err)
		return false
	}
	//Now check against the db.
	if o.UserField == "Username" {
		if o.LocalDB == "mysql" {
			return o.Mysql.CheckAcl(claims.Username, topic, clientid, acc)
		} else if o.LocalDB == "postgres" {
			return o.Postgres.CheckAcl(claims.Username, topic, clientid, acc)
		}
	}
	if o.LocalDB == "mysql" {
		return o.Mysql.CheckAcl(claims.Subject, topic, clientid, acc)
	} else if o.LocalDB == "postgres" {
		return o.Postgres.CheckAcl(claims.Subject, topic, clientid, acc)
	}
	return false
}

func (o JWT) jwtRequest(host, uri, token string, withTLS, verifyPeer bool, dataMap map[string]interface{}, port, paramsMode, responseMode string, urlValues url.Values) bool {

	// Don't do the request if the client is nil.
	if o.Client == nil {
		return false
	}

	tlsStr := "http://"

	if withTLS {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s%s", tlsStr, host, uri)
	if port != "" {
		fullUri = fmt.Sprintf("%s%s:%s%s", tlsStr, host, port, uri)
	}

	var resp *http.Response
	var err error
	var req *http.Request

	if paramsMode == "json" {
		dataJson, err := json.Marshal(dataMap)

		if err != nil {
			log.Errorf("marshal error: %s", err)
			return false
		}

		contentReader := bytes.NewReader(dataJson)
		req, err = http.NewRequest("POST", fullUri, contentReader)

		if err != nil {
			log.Errorf("req error: %s", err)
			return false
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest("POST", fullUri, strings.NewReader(urlValues.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(urlValues.Encode())))

		if err != nil {
			log.Errorf("req error: %s", err)
			return false
		}
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err = o.Client.Do(req)

	if err != nil {
		log.Errorf("error: %v", err)
		return false
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Errorf("read error: %s", err)
		return false
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Infof("error code: %d", resp.StatusCode)
		return false
	}

	if responseMode == "text" {

		//For test response, we expect "ok" or an error message.
		if string(body) != "ok" {
			log.Infof("api error: %s", string(body))
			return false
		}

	} else if responseMode == "json" {

		//For json response, we expect Ok and Error fields.
		response := Response{Ok: false, Error: ""}
		err = json.Unmarshal(body, &response)

		if err != nil {
			log.Errorf("unmarshal error: %s", err)
			return false
		}

		if !response.Ok {
			log.Infof("api error: %s", response.Error)
			return false
		}

	}

	log.Debugf("jwt request approved for %s", token)
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
	} else if o.LocalDB == "postgres" {
		err = o.Postgres.DB.Get(&count, o.UserQuery, username)
	}

	if err != nil {
		log.Debugf("local JWT get user error: %s", err)
		return false
	}

	if !count.Valid {
		log.Debugf("local JWT get user error: user %s not found", username)
		return false
	}

	if count.Int64 > 0 {
		return true
	}

	return false
}

func (o JWT) getClaims(tokenStr string) (*Claims, error) {

	jwtToken, err := jwt_go.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt_go.Token) (interface{}, error) {
		return o.Secret, nil
	})

	if err != nil {
		log.Debugf("jwt parse error: %s", err)
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

//Halt closes any db connection.
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
