package backends

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	h "net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type remoteJWTChecker struct {
	userUri       string
	superuserUri  string
	aclUri        string
	userAgent     string
	host          string
	port          string
	hostWhitelist []string
	withTLS       bool
	verifyPeer    bool

	paramsMode   string
	httpMethod   string
	responseMode string

	options tokenOptions

	client *h.Client
}

type Response struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

const (
	whitelistMagicForAnyHost = "*"
)

func NewRemoteJWTChecker(authOpts map[string]string, options tokenOptions, version string) (jwtChecker, error) {
	var checker = &remoteJWTChecker{
		withTLS:      false,
		verifyPeer:   false,
		responseMode: "status",
		paramsMode:   "json",
		httpMethod:   h.MethodPost,
		options:      options,
	}

	missingOpts := ""
	remoteOk := true

	if responseMode, ok := authOpts["jwt_response_mode"]; ok {
		if responseMode == "text" || responseMode == "json" {
			checker.responseMode = responseMode
		}
	}

	if paramsMode, ok := authOpts["jwt_params_mode"]; ok {
		if paramsMode == "form" {
			checker.paramsMode = paramsMode
		}
	}

	if httpMethod, ok := authOpts["jwt_http_method"]; ok {
		switch httpMethod {
		case h.MethodGet, h.MethodPut:
			checker.httpMethod = httpMethod
		}
	}

	if userUri, ok := authOpts["jwt_getuser_uri"]; ok {
		checker.userUri = userUri
	} else {
		remoteOk = false
		missingOpts += " jwt_getuser_uri"
	}

	if superuserUri, ok := authOpts["jwt_superuser_uri"]; ok {
		checker.superuserUri = superuserUri
	}

	if aclUri, ok := authOpts["jwt_aclcheck_uri"]; ok {
		checker.aclUri = aclUri
	} else {
		remoteOk = false
		missingOpts += " jwt_aclcheck_uri"
	}

	checker.userAgent = fmt.Sprintf("%s-%s", defaultUserAgent, version)
	if userAgent, ok := authOpts["jwt_user_agent"]; ok {
		checker.userAgent = userAgent
	}

	if hostname, ok := authOpts["jwt_host"]; ok {
		checker.host = hostname
	} else if options.parseToken {
		checker.host = ""
	} else {
		remoteOk = false
		missingOpts += " jwt_host"
	}

	if hostWhitelist, ok := authOpts["jwt_host_whitelist"]; ok {
		if hostWhitelist == whitelistMagicForAnyHost {
			log.Warning(
				"Backend host whitelisting is turned off. This is not secure and should not be used in " +
					"the production environment")
			checker.hostWhitelist = append(checker.hostWhitelist, whitelistMagicForAnyHost)
		} else {
			for _, host := range strings.Split(hostWhitelist, ",") {
				strippedHost := strings.TrimSpace(host)
				/* Not-so-strict check if we have a valid value (domain name or ip address with optional
				port) as a part of the host whitelist. TODO: Consider using more robust check, i.e.
				using "govalidator" or similar package instead. */
				if matched, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9-\.]+[a-zA-Z0-9](?:\:[0-9]+)?$`, strippedHost); !matched {
					return nil, errors.Errorf("JWT backend error: bad host %s in jwt_host_whitelist", strippedHost)
				}
				checker.hostWhitelist = append(checker.hostWhitelist, strippedHost)
			}
		}
	} else if checker.host == "" {
		remoteOk = false
		missingOpts += " jwt_host_whitelist"
	}

	if port, ok := authOpts["jwt_port"]; ok {
		checker.port = port
	} else {
		remoteOk = false
		missingOpts += " jwt_port"
	}

	if withTLS, ok := authOpts["jwt_with_tls"]; ok && withTLS == "true" {
		checker.withTLS = true
	}

	if verifyPeer, ok := authOpts["jwt_verify_peer"]; ok && verifyPeer == "true" {
		checker.verifyPeer = true
	}

	if !remoteOk {
		return nil, errors.Errorf("JWT backend error: missing remote options: %s", missingOpts)
	}

	checker.client = &h.Client{Timeout: 5 * time.Second}

	if !checker.verifyPeer {
		tr := &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		checker.client.Transport = tr
	}

	return checker, nil
}

func (o *remoteJWTChecker) GetUser(token string) (bool, error) {
	var dataMap map[string]interface{}
	var urlValues url.Values

	if o.options.parseToken {
		username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

		if err != nil {
			log.Printf("jwt remote get user error: %s", err)
			return false, err
		}

		dataMap = map[string]interface{}{
			"username": username,
		}

		urlValues = url.Values{
			"username": []string{username},
		}
	}

	return o.jwtRequest(o.userUri, token, dataMap, urlValues)
}

func (o *remoteJWTChecker) GetSuperuser(token string) (bool, error) {
	if o.superuserUri == "" {
		return false, nil
	}
	var dataMap map[string]interface{}
	var urlValues = url.Values{}

	if o.options.parseToken {
		username, err := getUsernameForToken(o.options, token, o.options.skipUserExpiration)

		if err != nil {
			log.Printf("jwt remote get superuser error: %s", err)
			return false, err
		}

		dataMap = map[string]interface{}{
			"username": username,
		}

		urlValues = url.Values{
			"username": []string{username},
		}
	}

	return o.jwtRequest(o.superuserUri, token, dataMap, urlValues)
}

func (o *remoteJWTChecker) CheckAcl(token, topic, clientid string, acc int32) (bool, error) {
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

	if o.options.parseToken {
		username, err := getUsernameForToken(o.options, token, o.options.skipACLExpiration)

		if err != nil {
			log.Printf("jwt remote check acl error: %s", err)
			return false, err
		}

		dataMap["username"] = username

		urlValues.Add("username", username)
	}

	return o.jwtRequest(o.aclUri, token, dataMap, urlValues)
}

func (o *remoteJWTChecker) Halt() {
	// NO-OP
}

func (o *remoteJWTChecker) jwtRequest(uri, token string, dataMap map[string]interface{}, urlValues url.Values) (bool, error) {

	// Don't do the request if the client is nil.
	if o.client == nil {
		return false, errors.New("jwt http client not initialized")
	}

	tlsStr := "http://"

	if o.withTLS {
		tlsStr = "https://"
	}

	host, err := o.getHost(token)
	if err != nil {
		return false, err
	}

	fullURI := fmt.Sprintf("%s%s%s", tlsStr, host, uri)
	// If "host" variable already has port set, do not use the value of jwt_port option from config.
	if !strings.Contains(host, ":") && o.port != "" {
		fullURI = fmt.Sprintf("%s%s:%s%s", tlsStr, host, o.port, uri)
	}

	var resp *h.Response
	var req *h.Request

	switch o.paramsMode {
	case "json":
		dataJSON, err := json.Marshal(dataMap)

		if err != nil {
			log.Errorf("marshal error: %s", err)
			return false, err
		}

		contentReader := bytes.NewReader(dataJSON)
		req, err = h.NewRequest(o.httpMethod, fullURI, contentReader)

		if err != nil {
			log.Errorf("req error: %s", err)
			return false, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", o.userAgent)
	default:
		req, err = h.NewRequest(o.httpMethod, fullURI, strings.NewReader(urlValues.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(urlValues.Encode())))
		req.Header.Set("User-Agent", o.userAgent)

		if err != nil {
			log.Errorf("req error: %s", err)
			return false, err
		}
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err = o.client.Do(req)

	if err != nil {
		log.Errorf("error: %v", err)
		return false, err
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Errorf("read error: %s", err)
		return false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Infof("error code: %d", resp.StatusCode)
		if resp.StatusCode >= 500 {
			err = fmt.Errorf("error code: %d", resp.StatusCode)
		}
		return false, err
	}

	if o.responseMode == "text" {

		//For test response, we expect "ok" or an error message.
		if string(body) != "ok" {
			log.Infof("api error: %s", string(body))
			return false, nil
		}

	} else if o.responseMode == "json" {

		//For json response, we expect Ok and Error fields.
		response := Response{Ok: false, Error: ""}
		err = json.Unmarshal(body, &response)

		if err != nil {
			log.Errorf("unmarshal error: %s", err)
			return false, err
		}

		if !response.Ok {
			log.Infof("api error: %s", response.Error)
			return false, nil
		}

	}

	log.Debugf("jwt request approved for %s", token)
	return true, nil
}

func (o *remoteJWTChecker) getHost(token string) (string, error) {
	if o.host != "" {
		return o.host, nil
	}

	// Actually this should never happen because of configuration sanity check. TODO: consider removing this condition.
	if !o.options.parseToken {
		errorString := fmt.Sprintf("impossible to obtain host for the authorization request - token parsing is turned off")
		return "", errors.New(errorString)
	}

	iss, err := getIssForToken(o.options, token, o.options.skipUserExpiration)
	if err != nil {
		errorString := fmt.Sprintf("cannot obtain host for the authorization request from token %s: %s", token, err)
		return "", errors.New(errorString)
	}

	if !o.isHostWhitelisted(iss) {
		errorString := fmt.Sprintf("host %s obtained from host is not whitelisted; rejecting", iss)
		return "", errors.New(errorString)
	}

	return iss, nil
}

func (o *remoteJWTChecker) isHostWhitelisted(host string) bool {
	if len(o.hostWhitelist) == 1 && o.hostWhitelist[0] == whitelistMagicForAnyHost {
		return true
	}

	for _, whitelistedHost := range o.hostWhitelist {
		if whitelistedHost == host {
			return true
		}
	}
	return false
}
