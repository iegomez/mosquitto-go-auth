package backends

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type JWT struct {
	Remote bool

	Postgres       Postgres
	Secret         string
	UserQuery      string
	SuperuserQuery string
	AclQuery       string

	Method       string
	UserUri      string
	SuperuserUri string
	AclUri       string
	Hostname     string
	Port         string
	Ip           string
	WithTLS      bool
	VerifyPeer   bool
}

// Claims defines the struct containing the token claims.
type Claims struct {
	jwt.StandardClaims

	// Username defines the identity of the user.
	Username string `json:"username"`
}

type Response struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewJWT(authOpts map[string]string) (JWT, error) {

	//Initialize with defaults
	var jwt = JWT{
		Remote:     false,
		Method:     "post",
		WithTLS:    false,
		VerifyPeer: false,
	}

	if remote, ok := authOpts["jwt_remote"]; ok && remote == "true" {
		jwt.Remote = true
	}

	//If remote, set remote api fields. Else, set jwt secret.

	if jwt.Remote {

		missingOpts := ""
		remoteOk := true

		if method, ok := authOpts["jwt_method"]; ok {
			jwt.Method = method
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

		if hostname, ok := authOpts["jwt_hostname"]; ok {
			jwt.Hostname = hostname
		} else {
			remoteOk = false
			missingOpts += " jwt_hostname"
		}

		if port, ok := authOpts["jwt_port"]; ok {
			jwt.Port = port
		} else {
			remoteOk = false
			missingOpts += " jwt_port"
		}

		if ip, ok := authOpts["jwt_ip"]; ok {
			jwt.Ip = ip
		} else {
			remoteOk = false
			missingOpts += " jwt_ip"
		}

		if withTLS, ok := authOpts["jwt_with_tls"]; ok && withTLS == "true" {
			jwt.WithTLS = true
		}

		if verifyPeer, ok := authOpts["jwt_verify_peer"]; ok && verifyPeer == "true" {
			jwt.VerifyPeer = true
		}

		if !remoteOk {
			log.Fatalf("JWT backend error: missing remote options%s.\n", missingOpts)
		}

	} else {

		missingOpts := ""
		localOk := true

		if secret, ok := authOpts["jwt_secret"]; ok {
			jwt.Secret = secret
		} else {
			log.Fatal("JWT backend error: missing jwt secret.\n")
		}

		if userQuery, ok := authOpts["jwt_userquery"]; ok {
			jwt.UserQuery = userQuery
		} else {
			localOk = false
			missingOpts += " jwt_userquery"
		}

		if superuserQuery, ok := authOpts["jwt_superquery"]; ok {
			jwt.SuperuserQuery = superuserQuery
		} else {
			localOk = false
			missingOpts += " jwt_superquery"
		}

		if aclQuery, ok := authOpts["jwt_aclquery"]; ok {
			jwt.AclQuery = aclQuery
		} else {
			localOk = false
			missingOpts += " jwt_aclquery"
		}

		if !localOk {
			log.Fatalf("JWT backend error: missing local options%s.\n", missingOpts)
		}

		//Try to create a postgres backend with these custom queries.
		postgres, err := NewPostgres(authOpts)
		if err != nil {
			log.Fatalf("JWT backend error: couldn't create postgres connector for local jwt: %s\n", err)
		}

		postgres.UserQuery = jwt.UserQuery
		postgres.SuperuserQuery = jwt.SuperuserQuery
		postgres.AclQuery = jwt.AclQuery

		jwt.Postgres = postgres

	}

	return jwt, nil
}

func (o JWT) GetUser(token, password string) bool {

	log.Printf("jwt getuser for %s\n", token)

	if o.Remote {
		dataMap := map[string]interface{}{
			"password": token,
		}
		return httpRequest(o.Method, o.Ip, o.UserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port)
	}

	//If not remote, get the claims and check against postgres for user.
	claims, err := o.getClaims(token)

	if err != nil {
		log.Printf("jwt get user error: %s\n", err)
	}
	//Now check against postgres
	return o.getLocalUser(claims.Username)

}

func (o JWT) GetSuperuser(token string) bool {

	log.Printf("jwt superuser for %s\n", token)
	if o.Remote {
		var dataMap map[string]interface{}
		return httpRequest(o.Method, o.Ip, o.SuperuserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port)
	}

	//If not remote, get the claims and check against postgres for user.
	claims, err := o.getClaims(token)

	if err != nil {
		log.Printf("jwt get superuser error: %s\n", err)
		return false
	}
	//Now check against postgres
	return o.Postgres.GetSuperuser(claims.Username)

}

func (o JWT) CheckAcl(token, topic, clientid string, acc int32) bool {

	log.Printf("jwt acl for %s\n", token)
	if o.Remote {
		dataMap := map[string]interface{}{
			"clientid": clientid,
			"topic":    topic,
			"acc":      acc,
		}
		return httpRequest(o.Method, o.Ip, o.AclUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port)
	}

	//If not remote, get the claims and check against postgres for user.
	claims, err := o.getClaims(token)

	if err != nil {
		log.Printf("jwt check acl error: %s\n", err)
		return false
	}
	//Now check against postgres
	return o.Postgres.CheckAcl(claims.Username, topic, clientid, acc)

}

func httpRequest(method, host, uri, token string, withTLS, verifyPeer bool, dataMap map[string]interface{}, port string) bool {

	tlsStr := "http://"

	if withTLS {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s:%s%s", tlsStr, host, port, uri)

	client := &http.Client{Timeout: 5 * time.Second}

	if !verifyPeer {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}

	dataJson, mErr := json.Marshal(dataMap)

	if mErr != nil {
		log.Printf("marshal error: %v\n", mErr)
		return false
	}

	contentReader := bytes.NewReader(dataJson)
	req, reqErr := http.NewRequest("POST", fullUri, contentReader)

	if reqErr != nil {
		log.Printf("req error: %v\n", reqErr)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("authorization", token)

	resp, err := client.Do(req)

	if err != nil {
		log.Printf("error: %v\n", err)
		return false
	}

	body, bErr := ioutil.ReadAll(resp.Body)

	if bErr != nil {
		log.Printf("read error: %v", bErr)
		return false
	}

	response := Response{Ok: false, Error: ""}

	jErr := json.Unmarshal(body, &response)

	if jErr != nil {
		log.Printf("unmarshal error: %v", jErr)
		return false
	}

	if resp.Status != "200 OK" {
		log.Printf("error code: %v\n", err)
		return false
	} else if !response.Ok {
		log.Printf("api error: %s", response.Error)
		return false
	}

	log.Printf("jwt request approved for %s\n", token)
	return true

}

//GetName return the backend's name
func (o JWT) GetName() string {
	return "JWT"
}

func (o JWT) getLocalUser(username string) bool {
	//If there's no superuser query, return false.
	if o.UserQuery == "" {
		return false
	}

	var count sql.NullInt64
	err := o.Postgres.DB.Get(&count, o.UserQuery, username)

	if err != nil {
		log.Printf("Local JWT get user error: %s\n", err)
		return false
	}

	if !count.Valid {
		log.Printf("Local JWT get user error: user %s not found.\n", username)
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
		log.Printf("jwt parse error: %s\n", err)
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, errors.New("jwt invalid token")
	}

	claims, ok := jwtToken.Claims.(*Claims)
	if !ok {
		// no need to use a static error, this should never happen
		log.Printf("api/auth: expected *Claims, got %T", jwtToken.Claims)
		return nil, errors.New("got strange claims")
	}

	return claims, nil
}
