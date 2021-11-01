package backends

import (
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func setupMockOAuthServer() (*httptest.Server, func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" || authHeader == "Bearer wrong_token" {
			http.Error(w, "Fail", 404)
		}

		w.Header().Set("Content-Type", "application/json")

		if authHeader == "Bearer mock_access_token_normaluser" {
			w.Write([]byte("{\"sub\":\"mock_user_id_0\",\"mqtt\":{\"superuser\":false,\"topics\":{\"read\":[\"/test/topic/read/#\",\"/test/topic/writeread/1\",\"/test/topic/pattern/username/%u\",\"/test/topic/pattern/clientid/%c\"],\"write\":[\"/test/topic/write/+/db\",\"/test/topic/writeread/1\"]}}}"))
		}
		if authHeader == "Bearer mock_access_token_superuser" {
			w.Write([]byte("{\"sub\":\"mock_user_id_1\",\"mqtt\":{\"superuser\":true,\"topics\":{\"read\":[\"/test/topic/read/#\",\"/test/topic/writeread/1\"],\"write\":[\"/test/topic/write/+/db\",\"/test/topic/writeread/1\"]}}}"))
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
			w.Write([]byte("access_token=mock_access_token_normaluser&scope=user&token_type=bearer&refresh_token=mock_refresh_token_normaluser&expires_in=0"))
			return
		}

		// register superuser
		if (username == "test_superuser" && password == "test_superuser") || accessToken == "mock_access_token_normaluser" {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			w.Write([]byte("access_token=mock_access_token_superuser&scope=user&token_type=bearer&refresh_token=mock_refresh_token_superuser&expires_in=0"))
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

func TestOauth2(t *testing.T) {

	authOpts := make(map[string]string)
	authOpts["oauth_client_id"] = "clientId"
	authOpts["oauth_client_secret"] = "clientSecret"
	cacheDuration := 2
	authOpts["oauth_cache_duration"] = strconv.Itoa(cacheDuration)
	authOpts["oauth_scopes"] = "all"

	Convey("If mandatory params are not set initialization should fail", t, func() {
		_, err := NewOauth2(authOpts, log.DebugLevel)
		So(err, ShouldBeError)
	})

	Convey("Test authentication and authorization using client credentials", t, func() {
		server, closeServer := setupMockOAuthServer()
		authOpts["oauth_token_url"] = server.URL + "/token"
		authOpts["oauth_userinfo_url"] = server.URL + "/userinfo"
		log.Infof("Start Testserver on location %s", server.URL)

		Convey("Given valid params NewOauth2() should return a Oauth2 backend instance", func() {
			oauth2, err := NewOauth2(authOpts, log.ErrorLevel)
			So(err, ShouldBeNil)

			Convey("Given unvalid username and password GetUser() should return false", func() {
				allowed, err := oauth2.GetUser("test_wrong_user", "test_wrong_user", "client_id")
				So(err, ShouldBeError)
				So(allowed, ShouldBeFalse)
			})

			// Normal User
			Convey("Given valid username and password GetUser() should return true", func() {
				allowed, err := oauth2.GetUser("test_normaluser", "test_normaluser", "client_id")
				So(err, ShouldBeNil)
				So(allowed, ShouldBeTrue)

				// Authorization
				Convey("When requesting read access for a topic included in oauth2-servers /userinfo 'read' response CheckAcl() should be true", func() {
					// Without username/client_id pattern
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/topic/read/sensor", "client_id", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
					// username pattern ("%u")
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/topic/pattern/username/test_normaluser", "clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
					// client_id pattern ("%c")
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/topic/pattern/clientid/test_clientid", "test_clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
				})
				Convey("When requesting write access for a topic included in oauth2-servers/userinfo 'write' response CheckAcl() should be true", func() {
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/topic/write/influx/db", "client_id", 2)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)

				})
				Convey("When requesting readwrite access for a topic included in oauth2-servers /userinfo 'read' and 'write' response CheckAcl() should be true", func() {
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/topic/writeread/1", "client_id", 3)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
				})
				Convey("When requesting read access for a topic included in oauth2-servers /userinfo 'read' response CheckAcl() should be false", func() {
					// Without username/client_id pattern
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/wrong_topic/read/sensor", "client_id", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
					// username pattern ("%u")
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/topic/pattern/username/test_wrong_user", "clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
					// client_id pattern ("%c")
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/topic/pattern/clientid/test_wrong_clientid", "test_clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
				})
				Convey("When requesting write access for a topic included in oauth2-servers/userinfo 'write' response CheckAcl() should be false", func() {
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/wrong_topic/write/influx/db", "client_id", 2)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
				})
				Convey("When requesting readwrite access for a topic included in oauth2-servers /userinfo 'read' and 'write' response CheckAcl() should be false", func() {
					allowed, err = oauth2.CheckAcl("test_normaluser", "/test/wrong_topic/writeread/1", "client_id", 3)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
				})
			})

			// Super User
			Convey("GetSuperuser() should return false if that user was not registered as superuser by GetUser()", func() {
				allowed, err := oauth2.GetSuperuser("test_normaluser")
				So(err, ShouldBeError)
				So(allowed, ShouldBeFalse)
			})
			Convey("Given valid superuser username and password GetUser() should return true", func() {
				allowed, err := oauth2.GetUser("test_superuser", "test_superuser", "client_id")
				So(err, ShouldBeNil)
				So(allowed, ShouldBeTrue)
				Convey("For a given superuser `username` GetSuperuser() should return true if that superuser was registered as superuser by GetUser()", func() {
					allowed, err := oauth2.GetSuperuser("test_superuser")
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
				})
				// Test cache expiry and token refreshment
				Convey("Refresh Tokens should be updated succesfully after cache expiry", func() {
					allowed, err = oauth2.CheckAcl("test_superuser", "/test/topic/read/sensor", "client_id", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
					allowed, err = oauth2.GetSuperuser("test_superuser")
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)

					time.Sleep(time.Duration(cacheDuration+1) * time.Second)

					allowed, err = oauth2.CheckAcl("test_superuser", "/test/topic/read/sensor", "client_id", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
					allowed, err = oauth2.GetSuperuser("test_superuser")
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)

					closeServer()
					time.Sleep(time.Duration(cacheDuration+1) * time.Second)

					allowed, err = oauth2.CheckAcl("test_superuser", "/test/topic/read/sensor", "client_id", 1)
					So(err, ShouldBeError)
					So(allowed, ShouldBeFalse)
					allowed, err = oauth2.GetSuperuser("test_superuser")
					So(err, ShouldBeError)
					So(allowed, ShouldBeFalse)
				})
			})
		})
	})

	Convey("Test authentication and authorization using access token", t, func() {
		server, closeServer := setupMockOAuthServer()
		defer closeServer()
		authOpts["oauth_token_url"] = server.URL + "/token"
		authOpts["oauth_userinfo_url"] = server.URL + "/userinfo"
		log.Infof("Start Testserver on location %s", server.URL)

		Convey("Given valid params NewOauth2() should return a Oauth2 backend instance", func() {
			oauth2, err := NewOauth2(authOpts, log.DebugLevel)
			So(err, ShouldBeNil)

			Convey("Given an unvalid access token GetUser() should return false", func() {
				allowed, err := oauth2.GetUser("wrong_access_token", "oauthbearer_empty_password", "client_id")
				So(err, ShouldBeError)
				So(allowed, ShouldBeFalse)
			})

			// Normal User
			Convey("Given a valid access token GetUser() should return true", func() {
				allowed, err := oauth2.GetUser("mock_access_token_normaluser", "oauthbearer_empty_password", "client_id")
				So(err, ShouldBeNil)
				So(allowed, ShouldBeTrue)

				// Authorization
				Convey("When requesting read access for a topic included in oauth2-servers /userinfo 'read' response CheckAcl() should be true", func() {
					// Without username/client_id pattern
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/topic/read/sensor", "client_id", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
					// username pattern ("%u")
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/topic/pattern/username/mock_access_token_normaluser", "clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
					// client_id pattern ("%c")
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/topic/pattern/clientid/test_clientid", "test_clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
				})
				Convey("When requesting write access for a topic included in oauth2-servers/userinfo 'write' response CheckAcl() should be true", func() {
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/topic/write/influx/db", "client_id", 2)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)

				})
				Convey("When requesting readwrite access for a topic included in oauth2-servers /userinfo 'read' and 'write' response CheckAcl() should be true", func() {
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/topic/writeread/1", "client_id", 3)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
				})
				Convey("When requesting read access for a topic included in oauth2-servers /userinfo 'read' response CheckAcl() should be false", func() {
					// Without username/client_id pattern
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/wrong_topic/read/sensor", "client_id", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
					// username pattern ("%u")
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/topic/pattern/username/test_wrong_user", "clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
					// client_id pattern ("%c")
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/topic/pattern/clientid/test_wrong_clientid", "test_clientid", 1)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
				})
				Convey("When requesting write access for a topic included in oauth2-servers/userinfo 'write' response CheckAcl() should be false", func() {
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/wrong_topic/write/influx/db", "client_id", 2)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
				})
				Convey("When requesting readwrite access for a topic included in oauth2-servers /userinfo 'read' and 'write' response CheckAcl() should be false", func() {
					allowed, err = oauth2.CheckAcl("mock_access_token_normaluser", "/test/wrong_topic/writeread/1", "client_id", 3)
					So(err, ShouldBeNil)
					So(allowed, ShouldBeFalse)
				})
			})

			// Super User
			Convey("GetSuperuser() should return false if that user was not registered as superuser by GetUser()", func() {
				allowed, err := oauth2.GetSuperuser("mock_access_token_normaluser")
				So(err, ShouldBeError)
				So(allowed, ShouldBeFalse)
			})
			Convey("Given valid superuser access token GetUser() should return true", func() {
				allowed, err := oauth2.GetUser("mock_access_token_superuser", "oauthbearer_empty_password", "client_id")
				So(err, ShouldBeNil)
				So(allowed, ShouldBeTrue)
				Convey("For a given superuser GetSuperuser() should return true if that superuser was registered as superuser by GetUser()", func() {
					allowed, err := oauth2.GetSuperuser("mock_access_token_superuser")
					So(err, ShouldBeNil)
					So(allowed, ShouldBeTrue)
				})
			})
		})
	})

}
