package backends

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	h "net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type HTTP struct {
	UserUri      string
	SuperuserUri string
	AclUri       string
	UserAgent    string
	Host         string
	Port         string
	WithTLS      bool
	VerifyPeer   bool
	ParamsMode   string
	httpMethod   string
	ResponseMode string
	Timeout      int
	Client       *h.Client
}

type HTTPResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewHTTP(authOpts map[string]string, logLevel log.Level, version string) (HTTP, error) {

	log.SetLevel(logLevel)

	//Initialize with defaults
	var http = HTTP{
		WithTLS:      false,
		VerifyPeer:   false,
		ResponseMode: "status",
		ParamsMode:   "json",
		httpMethod:   h.MethodPost,
	}

	missingOpts := ""
	httpOk := true

	if responseMode, ok := authOpts["http_response_mode"]; ok {
		if responseMode == "text" || responseMode == "json" {
			http.ResponseMode = responseMode
		}
	}

	if paramsMode, ok := authOpts["http_params_mode"]; ok {
		if paramsMode == "form" {
			http.ParamsMode = paramsMode
		}
	}

	if httpMethod, ok := authOpts["http_method"]; ok {
		switch httpMethod {
		case h.MethodGet, h.MethodPut:
			http.httpMethod = httpMethod
		}
	}

	if userUri, ok := authOpts["http_getuser_uri"]; ok {
		http.UserUri = userUri
	} else {
		httpOk = false
		missingOpts += " http_getuser_uri"
	}

	if superuserUri, ok := authOpts["http_superuser_uri"]; ok {
		http.SuperuserUri = superuserUri
	}

	if aclUri, ok := authOpts["http_aclcheck_uri"]; ok {
		http.AclUri = aclUri
	} else {
		httpOk = false
		missingOpts += " http_aclcheck_uri"
	}

	http.UserAgent = fmt.Sprintf("%s-%s", defaultUserAgent, version)
	if userAgent, ok := authOpts["http_user_agent"]; ok {
		http.UserAgent = userAgent
	}

	if host, ok := authOpts["http_host"]; ok {
		http.Host = host
	} else {
		httpOk = false
		missingOpts += " http_host"
	}

	if port, ok := authOpts["http_port"]; ok {
		http.Port = port
	} else {
		httpOk = false
		missingOpts += " http_port"
	}

	if withTLS, ok := authOpts["http_with_tls"]; ok && withTLS == "true" {
		http.WithTLS = true
	}

	if verifyPeer, ok := authOpts["http_verify_peer"]; ok && verifyPeer == "true" {
		http.VerifyPeer = true
	}

	http.Timeout = 5
	if timeoutString, ok := authOpts["http_timeout"]; ok {
		if timeout, err := strconv.Atoi(timeoutString); err == nil {
			http.Timeout = timeout
		} else {
			log.Errorf("unable to parse timeout: %s", err)
		}
	}

	if !httpOk {
		return http, errors.Errorf("HTTP backend error: missing remote options: %s", missingOpts)
	}

	http.Client = &h.Client{Timeout: time.Duration(http.Timeout) * time.Second}

	if !http.VerifyPeer {
		tr := &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.Client.Transport = tr
	}

	return http, nil
}

func (o HTTP) GetUser(username, password, clientid string) (bool, error) {

	var dataMap = map[string]interface{}{
		"username": username,
		"password": password,
		"clientid": clientid,
	}

	var urlValues = url.Values{
		"username": []string{username},
		"password": []string{password},
		"clientid": []string{clientid},
	}

	return o.httpRequest(o.UserUri, username, dataMap, urlValues)

}

func (o HTTP) GetSuperuser(username string) (bool, error) {

	if o.SuperuserUri == "" {
		return false, nil
	}

	var dataMap = map[string]interface{}{
		"username": username,
	}

	var urlValues = url.Values{
		"username": []string{username},
	}

	return o.httpRequest(o.SuperuserUri, username, dataMap, urlValues)

}

func (o HTTP) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	dataMap := map[string]interface{}{
		"username": username,
		"clientid": clientid,
		"topic":    topic,
		"acc":      acc,
	}

	var urlValues = url.Values{
		"username": []string{username},
		"clientid": []string{clientid},
		"topic":    []string{topic},
		"acc":      []string{strconv.Itoa(int(acc))},
	}

	return o.httpRequest(o.AclUri, username, dataMap, urlValues)

}

func (o HTTP) httpRequest(uri, username string, dataMap map[string]interface{}, urlValues map[string][]string) (bool, error) {

	// Don't do the request if the client is nil.
	if o.Client == nil {
		return false, errors.New("http client not initialized")
	}

	tlsStr := "http://"

	if o.WithTLS {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s%s", tlsStr, o.Host, uri)
	if o.Port != "" {
		fullUri = fmt.Sprintf("%s%s:%s%s", tlsStr, o.Host, o.Port, uri)
	}

	var resp *h.Response
	var err error

	if o.ParamsMode == "form" {
		if o.httpMethod != h.MethodPost && o.httpMethod != h.MethodPut {
			log.Errorf("error form param only supported for POST/PUT.")
			err = fmt.Errorf("form only supported for POST/PUT, error code: %d", 500)
			return false, err
		}

		resp, err = o.Client.PostForm(fullUri, urlValues)
	} else {
		var dataJson []byte
		dataJson, err = json.Marshal(dataMap)

		if err != nil {
			log.Errorf("marshal error: %s", err)
			return false, err
		}

		contentReader := bytes.NewReader(dataJson)
		var req *h.Request
		req, err = h.NewRequest(o.httpMethod, fullUri, contentReader)

		if err != nil {
			log.Errorf("req error: %s", err)
			return false, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", o.UserAgent)

		resp, err = o.Client.Do(req)
	}

	if err != nil {
		log.Errorf("http request error: %s", err)
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

	if o.ResponseMode == "text" {

		//For test response, we expect "ok" or an error message.
		if string(body) != "ok" {
			log.Infof("api error: %s", string(body))
			return false, nil
		}

	} else if o.ResponseMode == "json" {

		//For json response, we expect Ok and Error fields.
		response := HTTPResponse{Ok: false, Error: ""}
		err := json.Unmarshal(body, &response)

		if err != nil {
			log.Errorf("unmarshal error: %s", err)
			return false, err
		}

		if !response.Ok {
			log.Infof("api error: %s", response.Error)
			return false, nil
		}

	}

	log.Debugf("http request approved for %s", username)
	return true, nil

}

//GetName returns the backend's name
func (o HTTP) GetName() string {
	return "HTTP"
}

//Halt does nothing for http as there's no cleanup needed.
func (o HTTP) Halt() {
	//Do nothing
}
