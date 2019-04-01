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

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
)

type HTTP struct {
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

type HTTPResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewHTTP(authOpts map[string]string, logLevel log.Level) (HTTP, error) {

	log.SetLevel(logLevel)

	//Initialize with defaults
	var http = HTTP{
		WithTLS:      false,
		VerifyPeer:   false,
		ResponseMode: "status",
		ParamsMode:   "json",
	}

	//If remote, set remote api fields. Else, set jwt secret.

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

	if userUri, ok := authOpts["http_getuser_uri"]; ok {
		http.UserUri = userUri
	} else {
		httpOk = false
		missingOpts += " http_getuser_uri"
	}

	if superuserUri, ok := authOpts["http_superuser_uri"]; ok {
		http.SuperuserUri = superuserUri
	} else {
		httpOk = false
		missingOpts += " http_superuser_uri"
	}

	if aclUri, ok := authOpts["http_aclcheck_uri"]; ok {
		http.AclUri = aclUri
	} else {
		httpOk = false
		missingOpts += " http_aclcheck_uri"
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

	if !httpOk {
		return http, errors.Errorf("HTTP backend error: missing remote options%s.\n", missingOpts)
	}

	return http, nil
}

func (o HTTP) GetUser(username, password string) bool {

	var dataMap = map[string]interface{}{
		"username": username,
		"password": password,
	}

	var urlValues = url.Values{
		"username": []string{username},
		"password": []string{password},
	}

	return httpRequest(o.Host, o.UserUri, username, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)

}

func (o HTTP) GetSuperuser(username string) bool {

	var dataMap = map[string]interface{}{
		"username": username,
	}

	var urlValues = url.Values{
		"username": []string{username},
	}

	return httpRequest(o.Host, o.SuperuserUri, username, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)

}

func (o HTTP) CheckAcl(username, topic, clientid string, acc int32) bool {

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

	return httpRequest(o.Host, o.AclUri, username, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)

}

func httpRequest(host, uri, username string, withTLS, verifyPeer bool, dataMap map[string]interface{}, port, paramsMode, responseMode string, urlValues map[string][]string) bool {

	tlsStr := "http://"

	if withTLS {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s%s", tlsStr, host, uri)
	if port != "" {
		fullUri = fmt.Sprintf("%s%s:%s%s", tlsStr, host, port, uri)
	}

	client := &h.Client{Timeout: 5 * time.Second}

	if !verifyPeer {
		tr := &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}

	var resp *h.Response
	var err error

	if paramsMode == "form" {
		resp, err = client.PostForm(fullUri, urlValues)
	} else {
		dataJson, mErr := json.Marshal(dataMap)

		if mErr != nil {
			log.Errorf("marshal error: %v\n", mErr)
			return false
		}

		contentReader := bytes.NewReader(dataJson)
		req, reqErr := h.NewRequest("POST", fullUri, contentReader)

		if reqErr != nil {
			log.Errorf("req error: %v\n", reqErr)
			return false
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err = client.Do(req)
	}

	if err != nil {
		log.Errorf("POST error: %v\n", err)
		return false
	}

	body, bErr := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if bErr != nil {
		log.Errorf("read error: %v\n", bErr)
		return false
	}

	if resp.Status != "200" {
		log.Infof("Wrong http status: %s\n", resp.Status)
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
		response := HTTPResponse{Ok: false, Error: ""}
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

	log.Debugf("http request approved for %s\n", username)
	return true

}

//GetName returns the backend's name
func (o HTTP) GetName() string {
	return "HTTP"
}

//Halt does nothing for http as there's no cleanup needed.
func (o HTTP) Halt() {
	//Do nothing
}
