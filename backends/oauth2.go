package backends

import (
	"context"
	"encoding/json"
	"fmt"
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
	lastUserInfoUpate time.Time
	createdAt         time.Time
	updatedAt         time.Time
	client            *http.Client
	token             *go_oauth2.Token
}

type UserInfo struct {
	sub  string `json:"sub"`
	MQTT struct {
		Topics struct {
			Read  []string `json:"read"`
			Write []string `json:"write"`
		} `json:"topics"`
		Superuser bool `json:"superuser"`
	} `json:"mqtt"`
}

type Oauth2 struct {
	oauth2Config            go_oauth2.Config
	clientcredentialsConfig go_clientcredentials.Config
	tokenUrl                string
	userInfoURL             string
	userCache               map[string]userState
	cacheDuration           time.Duration
	version                 string
	scopesSplitted          []string
}

func NewOauth2(authOpts map[string]string, logLevel log.Level) (Oauth2, error) {
	log.SetLevel(logLevel)

	var oauth2 = Oauth2{}

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

	oauth2.oauth2Config = go_oauth2.Config{
		Scopes:      oauth2.scopesSplitted,
		RedirectURL: "",
		Endpoint: go_oauth2.Endpoint{
			TokenURL: tokenUrl,
			AuthURL:  "",
		},
	}

	if userInfoURL, ok := authOpts["oauth_userinfo_url"]; ok {
		placedOpts += "oauth_userinfo_url=" + userInfoURL + "\n"
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
		oauth2.scopesSplitted = strings.Split(strings.Replace(scopes, " ", "", -1), ",")
	} else {
		log.Infof("no scopes where specified, using scope `all`")
		oauth2.scopesSplitted = []string{"all"}
	}

	oauth2.userCache = make(map[string]userState)

	if oauth2Ok {
		log.Infof("OAuth Plugin initialized with configurations\n" + placedOpts)
	} else {
		return oauth2, errors.Errorf("Oauth2 backend error: missing remote options: %s", missingOpts)
	}

	return oauth2, nil
}

func (o Oauth2) GetUser(username, password, clientid string) (bool, error) {
	// Get token for the credentials and verify the user
	log.Debugf("Checking user with oauth plugin.")

	if password == "oauthbearer_empty_password" {
		return o.createUserWithToken(username, clientid)
	} else {
		return o.createUserWithCredentials(username, password, clientid)
	}
}

func (o Oauth2) GetSuperuser(username string) (bool, error) {
	// Function that checks if the user has admin privilies
	log.Debugf("Checking if user %s is a superuser.", username)

	cache, ok := o.userCache[username]
	if !ok {
		return false, fmt.Errorf("no entry in user cache for user %s", username)
	}

	if o.cacheIsValid(&cache) {
		log.Debugf("using cached userinfo to authorize")
	} else {
		log.Debugf("update userinfo using authorization server %s", o.userInfoURL)

		if !cache.token.Valid() {
			log.Warningf("Token for user %s invalid. Try to refresh.", username)
		}

		info, err := o.getUserInfo(cache.client)

		if err != nil {
			log.Errorf("Failed to receive UserInfo for user %s: %s", username, err)
			return false, err
		}

		cache.superuser = info.MQTT.Superuser
		cache.readTopics = info.MQTT.Topics.Read
		cache.writeTopics = info.MQTT.Topics.Write
		cache.updatedAt = time.Now()
	}

	log.Debugf("Check for superuser was %t", cache.superuser)
	o.userCache[username] = cache
	return cache.superuser, nil
}

func (o Oauth2) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	// Function that checks if the user has the right to access to an address
	log.Debugf("Checking if user %s is allowed to access topic %s with access %d.", username, topic, acc)

	cache, ok := o.userCache[username]
	if !ok {
		return false, fmt.Errorf("Have no entry in user cache for user %s", username)
	}

	if o.cacheIsValid(&cache) {
		log.Debugf("using cached userinfo to authorize")
	} else {
		log.Debugf("update userinfo using authorization server %s", o.userInfoURL)

		info, err := o.getUserInfo(cache.client)

		if err != nil {
			log.Errorf("Failed to receive UserInfo for user %s: %s", username, err)
			return false, err
		}

		cache.superuser = info.MQTT.Superuser
		cache.readTopics = info.MQTT.Topics.Read
		cache.writeTopics = info.MQTT.Topics.Write
		cache.updatedAt = time.Now()
	}

	log.Debugf("  user is superuser: %t", cache.superuser)
	log.Debugf("  topics with read permission %s", cache.readTopics)
	log.Debugf("  topics with write permission %s", cache.writeTopics)

	res := o.checkAccessToTopic(topic, acc, &cache, username, clientid)
	log.Debugf("ACL check was %t", res)
	return res, nil
}

func (o Oauth2) GetName() string {
	return "OAuth Plugin " + o.version
}

func (o Oauth2) Halt() {
	// Do whatever cleanup is needed.
}

func (o Oauth2) createUserWithCredentials(username, password, clientid string) (bool, error) {
	o.clientcredentialsConfig = go_clientcredentials.Config{
		ClientID:     username,
		ClientSecret: password,
		TokenURL:     o.tokenUrl,
	}

	token, err := o.clientcredentialsConfig.Token(context.Background())

	if err != nil {
		log.Println(err)
		return false, err
	}

	clientcredentialsClient := o.clientcredentialsConfig.Client(context.Background())

	o.userCache[username] = userState{
		username:  username,
		superuser: false,
		createdAt: time.Now(),
		updatedAt: time.Unix(0, 0),
		client:    clientcredentialsClient,
		token:     token,
	}

	return true, err
}

func (o Oauth2) createUserWithToken(accessToken, clientid string) (bool, error) {
	token := &go_oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}

	client := o.oauth2Config.Client(context.Background(), token)

	info, err := o.getUserInfo(client)

	if err != nil {
		log.Println(err)
		return false, err
	}

	o.userCache[accessToken] = userState{
		username:    accessToken,
		superuser:   info.MQTT.Superuser,
		createdAt:   time.Now(),
		updatedAt:   time.Now(),
		readTopics:  info.MQTT.Topics.Read,
		writeTopics: info.MQTT.Topics.Write,
		client:      client,
		token:       token,
	}

	return true, err
}

func (o Oauth2) getUserInfo(client *http.Client) (*UserInfo, error) {
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

func (o Oauth2) checkAccessToTopic(topic string, acc int32, cache *userState, username string, clientid string) bool {
	log.Debugf("Check for acl level %d", acc)

	// check read access
	if acc == 1 || acc == 4 {
		res := o.isTopicInList(cache.readTopics, topic, username, clientid)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == 2 {
		res := o.isTopicInList(cache.writeTopics, topic, username, clientid)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == 3 {
		res := o.isTopicInList(cache.readTopics, topic, username, clientid) && o.isTopicInList(cache.writeTopics, topic, username, clientid)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}

func (o Oauth2) cacheIsValid(cache *userState) bool {
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

func (o Oauth2) isTopicInList(topicList []string, searchedTopic string, username string, clientid string) bool {
	replacer := strings.NewReplacer("%u", username, "%c", clientid)

	for _, topicFromList := range topicList {
		if topics.Match(replacer.Replace(topicFromList), searchedTopic) {
			return true
		}
	}
	return false
}
