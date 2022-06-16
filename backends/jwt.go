package backends

import (
	jwtGo "github.com/golang-jwt/jwt"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type JWT struct {
	mode    string
	checker jwtChecker
}

type tokenOptions struct {
	parseToken         bool
	skipUserExpiration bool
	skipACLExpiration  bool
	secret             string
	userFieldKey       string
}

type jwtChecker interface {
	GetUser(username string) (bool, error)
	GetSuperuser(username string) (bool, error)
	CheckAcl(username, topic, clientid string, acc int32) (bool, error)
	Halt()
}

const (
	remoteMode        = "remote"
	localMode         = "local"
	jsMode            = "js"
	filesMode         = "files"
	claimsSubjectKey  = "sub"
	claimsUsernameKey = "username"
	claimsIssKey      = "iss"
)

func NewJWT(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer, version string) (*JWT, error) {
	log.SetLevel(logLevel)

	jwt := &JWT{}

	var err error
	var checker jwtChecker

	var options tokenOptions

	if parseToken, ok := authOpts["jwt_parse_token"]; ok && parseToken == "true" {
		options.parseToken = true
	}

	if skipUserExpiration, ok := authOpts["jwt_skip_user_expiration"]; ok && skipUserExpiration == "true" {
		options.skipUserExpiration = true
	}

	if skipACLExpiration, ok := authOpts["jwt_skip_acl_expiration"]; ok && skipACLExpiration == "true" {
		options.skipACLExpiration = true
	}

	if secret, ok := authOpts["jwt_secret"]; ok {
		options.secret = secret
	}

	if userField, ok := authOpts["jwt_userfield"]; ok && userField == "Username" {
		options.userFieldKey = claimsUsernameKey
	} else {
		options.userFieldKey = claimsSubjectKey
	}

	switch authOpts["jwt_mode"] {
	case jsMode:
		jwt.mode = jsMode
		checker, err = NewJsJWTChecker(authOpts, options)
	case localMode:
		jwt.mode = localMode
		checker, err = NewLocalJWTChecker(authOpts, logLevel, hasher, options)
	case remoteMode:
		jwt.mode = remoteMode
		checker, err = NewRemoteJWTChecker(authOpts, options, version)
	case filesMode:
		jwt.mode = filesMode
		checker, err = NewFilesJWTChecker(authOpts, logLevel, hasher, options)
	default:
		err = errors.New("unknown JWT mode")
	}

	if err != nil {
		return nil, err
	}

	jwt.checker = checker

	return jwt, nil
}

//GetUser authenticates a given user.
func (o *JWT) GetUser(token, password, clientid string) (bool, error) {
	return o.checker.GetUser(token)
}

//GetSuperuser checks if the given user is a superuser.
func (o *JWT) GetSuperuser(token string) (bool, error) {
	return o.checker.GetSuperuser(token)
}

//CheckAcl checks user authorization.
func (o *JWT) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
	return o.checker.CheckAcl(token, topic, clientid, acc)
}

//GetName returns the backend's name
func (o *JWT) GetName() string {
	return "JWT"
}

//Halt closes any db connection.
func (o *JWT) Halt() {
	o.checker.Halt()
}

func getJWTClaims(secret string, tokenStr string, skipExpiration bool) (*jwtGo.MapClaims, error) {

	jwtToken, err := jwtGo.ParseWithClaims(tokenStr, &jwtGo.MapClaims{}, func(token *jwtGo.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	expirationError := false
	if err != nil {
		if !skipExpiration {
			log.Debugf("jwt parse error: %s", err)
			return nil, err
		}

		if v, ok := err.(*jwtGo.ValidationError); ok && v.Errors == jwtGo.ValidationErrorExpired {
			expirationError = true
		}
	}

	if !jwtToken.Valid && !expirationError {
		return nil, errors.New("jwt invalid token")
	}

	claims, ok := jwtToken.Claims.(*jwtGo.MapClaims)
	if !ok {
		log.Debugf("jwt error: expected *MapClaims, got %T", jwtToken.Claims)
		return nil, errors.New("got strange claims")
	}

	return claims, nil
}

func getUsernameForToken(options tokenOptions, tokenStr string, skipExpiration bool) (string, error) {
	claims, err := getJWTClaims(options.secret, tokenStr, skipExpiration)

	if err != nil {
		return "", err
	}

	username, found := (*claims)[options.userFieldKey]
	if !found {
		return "", nil
	}

	usernameString, ok := username.(string)
	if !ok {
		log.Debugf("jwt error: username expected to be string, got %T", username)
		return "", errors.New("got strange username")
	}

	return usernameString, nil
}

func getClaimsForToken(options tokenOptions, tokenStr string, skipExpiration bool) (map[string]interface{}, error) {
	claims, err := getJWTClaims(options.secret, tokenStr, skipExpiration)
	if err != nil {
		return make(map[string]interface{}), err
	}

	return map[string]interface{}(*claims), nil
}

func getIssForToken(options tokenOptions, tokenStr string, skipExpiration bool) (string, error) {
	claims, err := getJWTClaims(options.secret, tokenStr, skipExpiration)

	if err != nil {
		return "", err
	}

	iss, found := (*claims)[claimsIssKey]
	if !found {
		return "", nil
	}

	issString, ok := iss.(string)
	if !ok {
		log.Debugf("jwt error: iss expected to be string, got %T", iss)
		return "", errors.New("got strange iss")
	}

	return issString, nil
}
