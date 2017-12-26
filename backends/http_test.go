package backends

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestHTTPAllJsonServer(t *testing.T) {

	username := "test_user"
	password := "test_password"
	topic := "test/topic"
	var acc = int64(1)
	clientId := "test_client"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		httpResponse := &HTTPResponse{
			Ok:    true,
			Error: "",
		}

		var jsonResponse []byte

		var data interface{}
		var params map[string]interface{}

		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()

		uErr := json.Unmarshal(body, &data)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")

		if uErr != nil {
			httpResponse.Ok = false
			httpResponse.Error = "Json unmarshal error"
		}

		params = data.(map[string]interface{})
		log.Printf("received params %v for path %s\n", params, r.URL.Path)

		if r.URL.Path == "/user" {
			if params["username"].(string) == username && params["password"].(string) == password {
				httpResponse.Ok = true
				httpResponse.Error = ""
			} else {
				httpResponse.Ok = false
				httpResponse.Error = "Wrong credentials."
			}
		} else if r.URL.Path == "/superuser" {
			if params["username"].(string) == username {
				httpResponse.Ok = true
				httpResponse.Error = ""
			} else {
				httpResponse.Ok = false
				httpResponse.Error = "Not a superuser."
			}
		} else if r.URL.Path == "/acl" {
			//uAcc := float64.(params["acc"])
			paramsAcc := int64(params["acc"].(float64))
			if params["username"].(string) == username && params["topic"].(string) == topic && params["clientid"].(string) == clientId && paramsAcc <= acc {
				httpResponse.Ok = true
				httpResponse.Error = ""
			} else {
				httpResponse.Ok = false
				httpResponse.Error = "Acl check failed."
			}
		}

		jsonResponse, mjErr := json.Marshal(httpResponse)
		if mjErr != nil {
			w.Write([]byte("error"))
		}

		w.Write(jsonResponse)

	}))

	defer mockServer.Close()

	log.Printf("Trying host: %s\n", mockServer.URL)

	authOpts := make(map[string]string)
	authOpts["http_params_mode"] = "json"
	authOpts["http_response_mode"] = "json"
	authOpts["http_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["http_port"] = ""
	authOpts["http_getuser_uri"] = "/user"
	authOpts["http_superuser_uri"] = "/superuser"
	authOpts["http_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewHTTP(authOpts)
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(username, password)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(username, "wrong_password")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(username)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser("not_admin")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 1)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 2)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, "fake/topic", clientId, 1)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientId that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, "fake_client_id", 1)
			So(authenticated, ShouldBeFalse)

		})

	})

}

func TestHTTPJsonStatusOnlyServer(t *testing.T) {

	username := "test_user"
	password := "test_password"
	topic := "test/topic"
	var acc = int64(1)
	clientId := "test_client"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var data interface{}
		var params map[string]interface{}

		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()

		uErr := json.Unmarshal(body, &data)

		if uErr != nil {
			w.WriteHeader(http.StatusBadRequest)
		}

		params = data.(map[string]interface{})
		log.Printf("received params %v for path %s\n", params, r.URL.Path)

		if r.URL.Path == "/user" {
			if params["username"].(string) == username && params["password"].(string) == password {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else if r.URL.Path == "/superuser" {
			if params["username"].(string) == username {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else if r.URL.Path == "/acl" {
			//uAcc := float64.(params["acc"])
			paramsAcc := int64(params["acc"].(float64))
			if params["username"].(string) == username && params["topic"].(string) == topic && params["clientid"].(string) == clientId && paramsAcc <= acc {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}

	}))

	defer mockServer.Close()

	log.Printf("Trying host: %s\n", mockServer.URL)

	authOpts := make(map[string]string)
	authOpts["http_params_mode"] = "json"
	authOpts["http_response_mode"] = "status"
	authOpts["http_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["http_port"] = ""
	authOpts["http_getuser_uri"] = "/user"
	authOpts["http_superuser_uri"] = "/superuser"
	authOpts["http_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewHTTP(authOpts)
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(username, password)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(username, "wrong_password")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(username)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser("not_admin")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 1)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 2)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, "fake/topic", clientId, 1)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientId that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, "fake_client_id", 1)
			So(authenticated, ShouldBeFalse)

		})

	})

}

func TestHTTPJsonTextResponseServer(t *testing.T) {

	username := "test_user"
	password := "test_password"
	topic := "test/topic"
	var acc = int64(1)
	clientId := "test_client"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var data interface{}
		var params map[string]interface{}

		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()

		uErr := json.Unmarshal(body, &data)

		w.WriteHeader(http.StatusOK)

		if uErr != nil {
			w.Write([]byte(uErr.Error()))
		}

		params = data.(map[string]interface{})
		log.Printf("received params %v for path %s\n", params, r.URL.Path)

		if r.URL.Path == "/user" {
			if params["username"].(string) == username && params["password"].(string) == password {
				w.Write([]byte("ok"))
			} else {
				w.Write([]byte("Wrong credentials."))
			}
		} else if r.URL.Path == "/superuser" {
			if params["username"].(string) == username {
				w.Write([]byte("ok"))
			} else {
				w.Write([]byte("Not a superuser"))
			}
		} else if r.URL.Path == "/acl" {
			//uAcc := float64.(params["acc"])
			paramsAcc := int64(params["acc"].(float64))
			if params["username"].(string) == username && params["topic"].(string) == topic && params["clientid"].(string) == clientId && paramsAcc <= acc {
				w.Write([]byte("ok"))
			} else {
				w.Write([]byte("Acl check failed."))
			}
		} else {
			w.Write([]byte("Path not found."))
		}

	}))

	defer mockServer.Close()

	log.Printf("Trying host: %s\n", mockServer.URL)

	authOpts := make(map[string]string)
	authOpts["http_params_mode"] = "json"
	authOpts["http_response_mode"] = "text"
	authOpts["http_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["http_port"] = ""
	authOpts["http_getuser_uri"] = "/user"
	authOpts["http_superuser_uri"] = "/superuser"
	authOpts["http_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewHTTP(authOpts)
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(username, password)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(username, "wrong_password")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(username)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser("not_admin")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 1)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 2)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, "fake/topic", clientId, 1)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientId that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, "fake_client_id", 1)
			So(authenticated, ShouldBeFalse)

		})

	})

}

func TestHTTPFormJsonResponseServer(t *testing.T) {

	username := "test_user"
	password := "test_password"
	topic := "test/topic"
	var acc = int64(1)
	clientId := "test_client"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		httpResponse := &HTTPResponse{
			Ok:    true,
			Error: "",
		}

		pfErr := r.ParseForm()
		if pfErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var jsonResponse []byte
		var params = r.Form

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/user" {
			if params["username"][0] == username && params["password"][0] == password {
				httpResponse.Ok = true
				httpResponse.Error = ""
			} else {
				httpResponse.Ok = false
				httpResponse.Error = "Wrong credentials."
			}
		} else if r.URL.Path == "/superuser" {
			if params["username"][0] == username {
				httpResponse.Ok = true
				httpResponse.Error = ""
			} else {
				httpResponse.Ok = false
				httpResponse.Error = "Not a superuser."
			}
		} else if r.URL.Path == "/acl" {
			paramsAcc, _ := strconv.ParseInt(params["acc"][0], 10, 64)
			if params["username"][0] == username && params["topic"][0] == topic && params["clientid"][0] == clientId && paramsAcc <= acc {
				httpResponse.Ok = true
				httpResponse.Error = ""
			} else {
				httpResponse.Ok = false
				httpResponse.Error = "Acl check failed."
			}
		}

		jsonResponse, mjErr := json.Marshal(httpResponse)
		if mjErr != nil {
			w.Write([]byte("error"))
		}

		w.Write(jsonResponse)

	}))

	defer mockServer.Close()

	log.Printf("Trying host: %s\n", mockServer.URL)

	authOpts := make(map[string]string)
	authOpts["http_params_mode"] = "form"
	authOpts["http_response_mode"] = "json"
	authOpts["http_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["http_port"] = ""
	authOpts["http_getuser_uri"] = "/user"
	authOpts["http_superuser_uri"] = "/superuser"
	authOpts["http_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewHTTP(authOpts)
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(username, password)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(username, "wrong_password")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(username)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser("not_admin")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 1)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 2)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, "fake/topic", clientId, 1)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientId that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, "fake_client_id", 1)
			So(authenticated, ShouldBeFalse)

		})

	})

}

func TestHTTPFormStatusOnlyServer(t *testing.T) {

	username := "test_user"
	password := "test_password"
	topic := "test/topic"
	var acc = int64(1)
	clientId := "test_client"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		pfErr := r.ParseForm()
		if pfErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var params = r.Form

		if r.URL.Path == "/user" {
			if params["username"][0] == username && params["password"][0] == password {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else if r.URL.Path == "/superuser" {
			if params["username"][0] == username {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else if r.URL.Path == "/acl" {
			paramsAcc, _ := strconv.ParseInt(params["acc"][0], 10, 64)
			if params["username"][0] == username && params["topic"][0] == topic && params["clientid"][0] == clientId && paramsAcc <= acc {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}

	}))

	defer mockServer.Close()

	log.Printf("Trying host: %s\n", mockServer.URL)

	authOpts := make(map[string]string)
	authOpts["http_params_mode"] = "form"
	authOpts["http_response_mode"] = "status"
	authOpts["http_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["http_port"] = ""
	authOpts["http_getuser_uri"] = "/user"
	authOpts["http_superuser_uri"] = "/superuser"
	authOpts["http_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewHTTP(authOpts)
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(username, password)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(username, "wrong_password")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(username)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser("not_admin")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 1)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 2)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, "fake/topic", clientId, 1)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientId that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, "fake_client_id", 1)
			So(authenticated, ShouldBeFalse)

		})

	})

}

func TestHTTPFormTextResponseServer(t *testing.T) {

	username := "test_user"
	password := "test_password"
	topic := "test/topic"
	var acc = int64(1)
	clientId := "test_client"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusOK)

		pfErr := r.ParseForm()
		if pfErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var params = r.Form

		if r.URL.Path == "/user" {
			if params["username"][0] == username && params["password"][0] == password {
				w.Write([]byte("ok"))
			} else {
				w.Write([]byte("Wrong credentials."))
			}
		} else if r.URL.Path == "/superuser" {
			if params["username"][0] == username {
				w.Write([]byte("ok"))
			} else {
				w.Write([]byte("Not a superuser"))
			}
		} else if r.URL.Path == "/acl" {
			paramsAcc, _ := strconv.ParseInt(params["acc"][0], 10, 64)
			if params["username"][0] == username && params["topic"][0] == topic && params["clientid"][0] == clientId && paramsAcc <= acc {
				w.Write([]byte("ok"))
			} else {
				w.Write([]byte("Acl check failed."))
			}
		} else {
			w.Write([]byte("Path not found."))
		}

	}))

	defer mockServer.Close()

	log.Printf("Trying host: %s\n", mockServer.URL)

	authOpts := make(map[string]string)
	authOpts["http_params_mode"] = "form"
	authOpts["http_response_mode"] = "text"
	authOpts["http_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["http_port"] = ""
	authOpts["http_getuser_uri"] = "/user"
	authOpts["http_superuser_uri"] = "/superuser"
	authOpts["http_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewHTTP(authOpts)
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(username, password)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(username, "wrong_password")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(username)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser("not_admin")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 1)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, clientId, 2)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, "fake/topic", clientId, 1)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientId that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(username, topic, "fake_client_id", 1)
			So(authenticated, ShouldBeFalse)

		})

	})

}
