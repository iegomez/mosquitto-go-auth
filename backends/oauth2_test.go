package backends

import (
	"encoding/json"
	"fmt"
	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type oauth2ServerUserinfoResponse struct {
	Sub  string `json:"sub"`
	MQTT struct {
		Topics struct {
			Read      []string `json:"read"`
			Write     []string `json:"write"`
			Subscribe []string
		} `json:"topics"`
		Superuser bool `json:"superuser"`
	} `json:"mqtt"`
}

func setupMockOAuthServer() (*httptest.Server, func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" || authHeader == "Bearer wrong_token" {
			http.Error(w, "Fail", 404)
		}

		w.Header().Set("Content-Type", "application/json")

		if authHeader == "Bearer mock_access_token_normaluser" {
			response := new(UserInfo)
			response.Sub = "mock_user_id_0"
			response.MQTT.Topics.Read = []string{
				"/test/topic/read/#",
				"/test/topic/writeread/1",
				"/test/topic/pattern/username/%u",
				"/test/topic/pattern/clientid/%c",
			}
			response.MQTT.Topics.Write = []string{
				"/test/topic/write/+/db",
				"/test/topic/writeread/1",
			}
			response.MQTT.Topics.Subscribe = []string{
				"/test/topic/subscribe/1",
			}
			response.MQTT.Topics.Deny = []string{
				"/test/topic/deny/1",
			}
			response.MQTT.Superuser = false

			str, _ := json.Marshal(response)
			w.Write(str)
		}
		if authHeader == "Bearer mock_access_token_superuser" {
			response := new(oauth2ServerUserinfoResponse)
			response.Sub = "mock_user_id_1"
			response.MQTT.Topics.Read = []string{
				"/test/topic/read/#",
				"/test/topic/writeread/1",
			}
			response.MQTT.Topics.Write = []string{
				"/test/topic/write/+/db",
				"/test/topic/writeread/1",
			}
			response.MQTT.Superuser = true

			str, _ := json.Marshal(response)
			w.Write(str)
		}
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Log Request
		log.Infof("Server received request: %s", r.URL.String())
		header := ""
		for headerKey, headerValueList := range r.Header {
			header += headerKey + "="
			for _, value := range headerValueList {
				header += value + ", "
			}
		}
		log.Infof("Request Headers: %s", header)

		accessToken := r.Form.Get("access_token")
		// grantType := r.Form.Get("grant_type")
		username, password, _ := r.BasicAuth()

		// register normal user
		if (username == "test_normaluser" && password == "test_normaluser") || (username == "test_pattern_user") || accessToken == "mock_access_token_normaluser" {
			// Should return acccess token back to the user
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")

			response := url.Values{
				"access_token": {"mock_access_token_normaluser"},
				"scope":        {"user"},
				"token_type":   {"bearer"},
				"expires_in":   {"0"},
			}

			str := response.Encode()
			w.Write([]byte(str))

			return
		}

		// register superuser
		if (username == "test_superuser" && password == "test_superuser") || accessToken == "mock_access_token_normaluser" {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")

			response := url.Values{
				"access_token": {"mock_access_token_superuser"},
				"scope":        {"user"},
				"token_type":   {"bearer"},
				"expires_in":   {"0"},
			}

			str := response.Encode()
			w.Write([]byte(str))

			return
		}

		http.Error(w, "Wrong credentials", 404)
	})

	server := httptest.NewServer(mux)

	return server, func() {
		server.Close()
		log.Infof("Close Testserver")
	}
}

func UserTests(username string, password string, oauth2 *Oauth2) {
	Convey("Given unvalid username and password combination GetUser() should return false", func() {
		allowed, err := oauth2.GetUser(username, "test_wrong_password", "client_id")
		So(err, ShouldBeError)
		So(allowed, ShouldBeFalse)
	})

	// Normal User
	Convey("Given valid username and password GetUser() should return true", func() {
		allowed, err := oauth2.GetUser(username, password, "client_id")
		So(err, ShouldBeNil)
		So(allowed, ShouldBeTrue)

		// Authorization
		Convey("When checking none access for a topic included in oauth2-server /userinfo 'read', 'write', 'subscribe' or 'deny' response CheckAcl should be false", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/read/1", "client_id", MOSQ_ACL_NONE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
			allowed, err = oauth2.CheckAcl(username, "/test/topic/write/1/db", "client_id", MOSQ_ACL_NONE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
			allowed, err = oauth2.CheckAcl(username, "/test/topic/subscribe/1", "client_id", MOSQ_ACL_NONE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
			allowed, err = oauth2.CheckAcl(username, "/test/topic/deny/1", "client_id", MOSQ_ACL_NONE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
		})
		Convey("When checking none access for a topic not included in oauth2-server /userinfo 'read', 'write', 'subscribe' and 'deny' response CheckAcl should be true", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/nothing/1", "client_id", MOSQ_ACL_NONE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
		})
		Convey("When checking if topic access is denied explicitly and that topic is included in oauth2-servers /userinfo 'deny' response CheckAcl() should be true", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/deny/1", "client_id", MOSQ_ACL_DENY)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
		})
		Convey("When checking if topic access is denied explicitly and that topic is not included in oauth2-servers /userinfo 'deny' response CheckAcl() should be false", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/deny/wrong_topic", "client_id", MOSQ_ACL_DENY)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
		})
		// // Grant access
		Convey("When requesting read access for a topic included in oauth2-servers /userinfo 'read' response CheckAcl() should be true", func() {
			// Without username/client_id pattern
			allowed, err = oauth2.CheckAcl(username, "/test/topic/read/sensor", "client_id", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
			// username pattern ("%u")
			allowed, err = oauth2.CheckAcl(username, fmt.Sprintf("/test/topic/pattern/username/%s", username), "clientid", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
			// client_id pattern ("%c")
			allowed, err = oauth2.CheckAcl(username, "/test/topic/pattern/clientid/test_clientid", "test_clientid", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
		})
		Convey("When requesting write access for a topic included in oauth2-servers/userinfo 'write' response CheckAcl() should be true", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/write/influx/db", "client_id", MOSQ_ACL_WRITE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
		})
		Convey("When requesting readwrite access for a topic included in oauth2-servers /userinfo 'read' and 'write' response CheckAcl() should be true", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/writeread/1", "client_id", MOSQ_ACL_READWRITE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
		})
		Convey("When requesting subscribe access for a topic included in oauth2-servers /userinfo 'subscribe' response CheckAcl() should be true", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/subscribe/1", "client_id", MOSQ_ACL_SUBSCRIBE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
		})
		// // Deny access
		Convey("When requesting read access for a topic not included in oauth2-servers /userinfo 'read' response CheckAcl() should be false", func() {
			// Without username/client_id pattern
			allowed, err = oauth2.CheckAcl(username, "/test/wrong_topic/read/sensor", "client_id", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
			// username pattern ("%u")
			allowed, err = oauth2.CheckAcl(username, "/test/topic/pattern/username/test_wrong_user", "clientid", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
			// client_id pattern ("%c")
			allowed, err = oauth2.CheckAcl(username, "/test/topic/pattern/clientid/test_wrong_clientid", "test_clientid", MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
		})
		Convey("When requesting write access for a topic not included in oauth2-servers/userinfo 'write' response CheckAcl() should be false", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/wrong_topic/write/influx/db", "client_id", MOSQ_ACL_WRITE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
		})
		Convey("When requesting readwrite access for a topic not included in oauth2-servers /userinfo 'read' and 'write' response CheckAcl() should be false", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/wrong_topic/writeread/1", "client_id", MOSQ_ACL_READWRITE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
		})
		Convey("When requesting subscribe access for a topic not included in oauth2-servers /userinfo 'subscribe' response CheckAcl() should be false", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/subscribe/wrong_topic", "client_id", MOSQ_ACL_SUBSCRIBE)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeFalse)
		})
	})
}

func SuperUserTests(username string, password string, oauth2 *Oauth2, closeServer func()) {
	cacheDuration := oauth2.cacheDuration

	Convey("GetSuperuser() should return false if that user was not registered as superuser by GetUser()", func() {
		allowed, err := oauth2.GetSuperuser(username)
		So(err, ShouldBeError)
		So(allowed, ShouldBeFalse)
	})
	Convey("Given valid superuser username and password GetUser() should return true", func() {
		allowed, err := oauth2.GetUser(username, password, "client_id")
		So(err, ShouldBeNil)
		So(allowed, ShouldBeTrue)
		Convey("For a given superuser `username` GetSuperuser() should return true if that superuser was registered as superuser by GetUser()", func() {
			allowed, err := oauth2.GetSuperuser(username)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
		})
		// Test cache expiry and token refreshment
		Convey("Refresh Tokens should be updated succesfully after cache expiry", func() {
			allowed, err = oauth2.CheckAcl(username, "/test/topic/read/sensor", "client_id", 1)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
			allowed, err = oauth2.GetSuperuser(username)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)

			time.Sleep(cacheDuration + 1*time.Second)

			allowed, err = oauth2.CheckAcl(username, "/test/topic/read/sensor", "client_id", 1)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)
			allowed, err = oauth2.GetSuperuser(username)
			So(err, ShouldBeNil)
			So(allowed, ShouldBeTrue)

			closeServer()
			time.Sleep(cacheDuration + 1*time.Second)

			allowed, err = oauth2.CheckAcl(username, "/test/topic/read/sensor", "client_id", 1)
			So(err, ShouldBeError)
			So(allowed, ShouldBeFalse)
			allowed, err = oauth2.GetSuperuser(username)
			So(err, ShouldBeError)
			So(allowed, ShouldBeFalse)
		})
	})
}

func TestOauth2(t *testing.T) {

	authOpts := make(map[string]string)
	authOpts["oauth_client_id"] = "clientId"
	authOpts["oauth_client_secret"] = "clientSecret"
	authOpts["oauth_cache_duration"] = "2"
	authOpts["oauth_scopes"] = "all"

	Convey("If mandatory params are not set initialization should fail", t, func() {
		_, err := NewOauth2(authOpts, log.DebugLevel)
		So(err, ShouldBeError)
	})

	Convey("Test authentication and authorization using client credentials", t, func() {
		server, closeServer := setupMockOAuthServer()
		defer closeServer()
		authOpts["oauth_token_url"] = server.URL + "/token"
		authOpts["oauth_userinfo_url"] = server.URL + "/userinfo"
		log.Infof("Started Testserver on location %s", server.URL)
		Convey("Given valid params NewOauth2() should return a Oauth2 backend instance", func() {
			oauth2, err := NewOauth2(authOpts, log.ErrorLevel)
			So(err, ShouldBeNil)
			UserTests("test_normaluser", "test_normaluser", oauth2)
			SuperUserTests("test_superuser", "test_superuser", oauth2, closeServer)
		})
	})

	Convey("Test authentication and authorization using access token", t, func() {
		server, closeServer := setupMockOAuthServer()
		defer closeServer()
		authOpts["oauth_token_url"] = server.URL + "/token"
		authOpts["oauth_userinfo_url"] = server.URL + "/userinfo"
		log.Infof("Start Testserver on location %s", server.URL)
		Convey("Given valid params NewOauth2() should return a Oauth2 backend instance", func() {
			oauth2, err := NewOauth2(authOpts, log.ErrorLevel)
			So(err, ShouldBeNil)
			UserTests("mock_access_token_normaluser", "oauthbearer_empty_password", oauth2)
			SuperUserTests("mock_access_token_superuser", "oauthbearer_empty_password", oauth2, closeServer)
		})
	})

}
