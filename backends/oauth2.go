package backends

import (
	"context"
	"encoding/json"
	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	go_oauth2 "golang.org/x/oauth2"
	go_clientcredentials "golang.org/x/oauth2/clientcredentials"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type userState struct {
	username          string
	superuser         bool
	readTopics        []string
	writeTopics       []string
	subscribeTopics   []string
	denyTopics        []string
	lastUserInfoUpate time.Time
	createdAt         time.Time
	updatedAt         time.Time
	client            *http.Client
	token             *go_oauth2.Token
}

type UserInfo struct {
	Sub  string `json:"sub"`
	MQTT struct {
		Topics struct {
			Read      []string `json:"read"`
			Write     []string `json:"write"`
			Subscribe []string `json:"subscribe"`
			Deny      []string `json:"deny"`
		} `json:"topics"`
		Superuser bool `json:"superuser"`
	} `json:"mqtt"`
}

type Oauth2 struct {
	tokenUrl      string
	userInfoURL   string
	userCache     map[string]userState
	cacheDuration time.Duration
	version       string
	scopesSplit   []string
}

func NewOauth2(authOpts map[string]string, logLevel log.Level) (*Oauth2, error) {
	log.SetLevel(logLevel)

	var oauth2 = &Oauth2{}
	oauth2.version = "1.0.0"

	placedOpts := ""
	missingOpts := ""
	oauth2Ok := true

	tokenUrl, ok := authOpts["oauth_token_url"]
	if ok {
		oauth2.tokenUrl = tokenUrl
		placedOpts += "oauth_token_url=" + tokenUrl + "\n"
	} else {
		oauth2Ok = false
		missingOpts += " oauth_token_url"
	}

	if userInfoURL, ok := authOpts["oauth_userinfo_url"]; ok {
		oauth2.userInfoURL = userInfoURL
	} else {
		oauth2Ok = false
		missingOpts += " oauth_userinfo_url"
	}

	if cacheDurationSeconds, ok := authOpts["oauth_cache_duration"]; ok {
		if durationInt, err := strconv.Atoi(cacheDurationSeconds); err == nil {
			placedOpts += "oauth_cache_duration=" + cacheDurationSeconds + "\n"
			oauth2.cacheDuration = time.Duration(durationInt) * time.Second
		} else {
			log.Errorf("unable to parse cacheDurationSeconds: %s", err)
		}
	} else {
		oauth2Ok = false
		missingOpts += " oauth_cache_duration"
	}

	if scopes, ok := authOpts["oauth_scopes"]; ok {
		placedOpts += "oauth_scopes=" + scopes + "\n"
		oauth2.scopesSplit = strings.Split(strings.Replace(scopes, " ", "", -1), ",")
	} else {
		log.Infof("no scopes where specified, using scope `all`")
		oauth2.scopesSplit = []string{"all"}
	}

	oauth2.userCache = make(map[string]userState)

	if oauth2Ok {
		log.Infof("OAuth Plugin initialized with configurations\n" + placedOpts)
	} else {
		return oauth2, errors.Errorf("Oauth2 backend error: missing remote options: %s", missingOpts)
	}

	return oauth2, nil
}

func (o *Oauth2) GetUser(username, password, clientid string) (bool, error) {
	if password == "oauthbearer_empty_password" {
		return o.createUserWithToken(username, clientid)
	} else {
		return o.createUserWithCredentials(username, password, clientid)
	}
}

func (o *Oauth2) GetSuperuser(username string) (bool, error) {
	// Function that checks if the user has admin privilies
	log.Debugf("Checking if user %s is a superuser.", username)

	cache, ok := o.userCache[username]
	if !ok {
		log.Infof("no entry in user cache for user %s", username)
		return false, nil
	}

	err := o.updateCache(&cache)
	if err != nil {
		return false, err
	}

	log.Debugf("Check for superuser was %t", cache.superuser)
	o.userCache[username] = cache
	return cache.superuser, nil
}

func (o *Oauth2) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	// Function that checks if the user has the right to access a topic
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache, ok := o.userCache[username]
	if !ok {
		log.Infof("no entry in user cache for user %s", username)
		return false, nil
	}

	err := o.updateCache(&cache)
	if err != nil {
		return false, err
	}

	res := o.checkAccessToTopic(topic, acc, &cache, username, clientid)
	log.Debugf("ACL check was %t", res)
	return res, nil
}

func (o *Oauth2) GetName() string {
	return "OAuth2 backend, version " + o.version
}

func (o *Oauth2) Halt() {
	// Do whatever cleanup is needed.
}

func (o *Oauth2) updateCache(cache *userState) error {

	if o.cacheIsValid(cache) {
		log.Debugf("using cached userinfo for user '%s' to authorize", cache.username)
	} else {
		log.Debugf("update userinfo for user '%s' using authorization server %s", cache.username, o.userInfoURL)

		info, err := o.getUserInfo(cache.client)

		if err != nil {
			log.Errorf("Failed to receive UserInfo for user %s: %s", cache.username, err)
			return err
		}

		cache.superuser = info.MQTT.Superuser
		cache.readTopics = info.MQTT.Topics.Read
		cache.writeTopics = info.MQTT.Topics.Write
		cache.subscribeTopics = info.MQTT.Topics.Subscribe
		cache.denyTopics = info.MQTT.Topics.Deny
		cache.updatedAt = time.Now()
	}

	log.Debugf("  user is superuser: %t", cache.superuser)
	log.Debugf("  topics with read permission: %s", cache.readTopics)
	log.Debugf("  topics with write permission: %s", cache.writeTopics)
	log.Debugf("  topics with subscribe permission: %s", cache.subscribeTopics)
	log.Debugf("  denied topics: %s", cache.denyTopics)

	return nil
}

func (o *Oauth2) createUserWithCredentials(username, password, clientid string) (bool, error) {
	clientcredentialsConfig := go_clientcredentials.Config{
		ClientID:     username,
		ClientSecret: password,
		TokenURL:     o.tokenUrl,
	}

	clientcredentialsClient := clientcredentialsConfig.Client(context.Background())

	o.userCache[username] = userState{
		username:  username,
		superuser: false,
		createdAt: time.Now(),
		updatedAt: time.Unix(0, 0),
		client:    clientcredentialsClient,
	}

	cache, _ := o.userCache[username]
	err := o.updateCache(&cache)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (o *Oauth2) createUserWithToken(accessToken, clientid string) (bool, error) {
	token := &go_oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}

	oauth2Config := go_oauth2.Config{
		Scopes:      o.scopesSplit,
		RedirectURL: "",
		Endpoint: go_oauth2.Endpoint{
			TokenURL: o.tokenUrl,
			AuthURL:  "",
		},
	}

	client := oauth2Config.Client(context.Background(), token)

	o.userCache[accessToken] = userState{
		username:  accessToken,
		createdAt: time.Now(),
		updatedAt: time.Unix(0, 0),
		client:    client,
	}

	cache, _ := o.userCache[accessToken]
	err := o.updateCache(&cache)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (o *Oauth2) getUserInfo(client *http.Client) (*UserInfo, error) {
	req, _ := http.NewRequest("GET", o.userInfoURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	info := UserInfo{}

	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

func (o *Oauth2) checkAccessToTopic(topic string, acc int32, cache *userState, username string, clientid string) bool {
	log.Debugf("Check for acl level %d", acc)

	if acc == MOSQ_ACL_NONE {
		resRead := !o.isTopicInList(cache.readTopics, topic, username, clientid)
		resWrite := !o.isTopicInList(cache.writeTopics, topic, username, clientid)
		resSubscribe := !o.isTopicInList(cache.subscribeTopics, topic, username, clientid)
		resDeny := !o.isTopicInList(cache.denyTopics, topic, username, clientid)
		res := resRead && resWrite && resSubscribe && resDeny
		log.Debugf("ACL for none was %t", res)
		return res
	}

	if acc == MOSQ_ACL_READ {
		res := o.isTopicInList(cache.readTopics, topic, username, clientid)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	if acc == MOSQ_ACL_WRITE {
		res := o.isTopicInList(cache.writeTopics, topic, username, clientid)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	if acc == MOSQ_ACL_READWRITE {
		resRead := o.isTopicInList(cache.readTopics, topic, username, clientid)
		resWrite := o.isTopicInList(cache.writeTopics, topic, username, clientid)
		res := resRead && resWrite
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}

	if acc == MOSQ_ACL_SUBSCRIBE {
		res := o.isTopicInList(cache.subscribeTopics, topic, username, clientid)
		log.Debugf("ACL for subscribe was %t", res)
		return res
	}

	if acc == MOSQ_ACL_DENY {
		res := o.isTopicInList(cache.denyTopics, topic, username, clientid)
		log.Debugf("ACL for deny was %t", res)
		return res
	}

	return false
}

func (o *Oauth2) cacheIsValid(cache *userState) bool {
	log.Debugf("Cache Expiary: %s", o.cacheDuration)
	log.Debugf("Last Update: %s", cache.updatedAt)
	log.Debugf("Difference to now: %s", time.Now().Sub(cache.updatedAt))

	// function tests if the cache of the user is still valid
	if o.cacheDuration == 0 {
		return false
	}

	if (time.Now().Sub(cache.updatedAt)) < o.cacheDuration {
		return true
	}
	return false
}

func (o *Oauth2) isTopicInList(topicList []string, searchedTopic string, username string, clientid string) bool {
	replacer := strings.NewReplacer("%u", username, "%c", clientid)

	for _, topicFromList := range topicList {
		if topics.Match(replacer.Replace(topicFromList), searchedTopic) {
			return true
		}
	}
	return false
}
