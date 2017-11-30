package main

import "C"

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-redis/redis"
	bes "github.com/iegomez/mosquitto-go-auth-plugin/backends"
)

type Backend interface {
	GetUser(username, password string) bool
	GetSuperuser(username string) bool
	CheckAcl(username, topic, clientId string, acc int32) bool
	GetName() string
}

type CommonData struct {
	Backends         []Backend
	Postgres         bes.Postgres
	Files            bes.Files
	Jwt              bes.JWT
	Superusers       []string
	AclCacheSeconds  int32
	AuthCacheSeconds int32
	Redis            *redis.Client
}

//Cache stores necessary values for Redis cache
type Cache struct {
	Host     string
	Port     string
	Password string
	DB       string
}

var allowedBackends = map[string]bool{
	"postgres": true,
	"jwt":      true,
	"redis":    true,
	"http":     true,
	"files":    true,
}
var backends []string
var authOpts map[string]string
var cache Cache
var commonData CommonData

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int) {

	//Initialize Cache with default values
	cache = Cache{
		Host:     "localhost",
		Port:     "6379",
		Password: "",
		DB:       "0",
	}

	commonBackends := make([]Backend, len(allowedBackends), len(allowedBackends))
	superusers := make([]string, 10, 10)

	//Initialize common struct with default and given values
	commonData = CommonData{
		Backends:         commonBackends,
		Superusers:       superusers,
		AclCacheSeconds:  30,
		AuthCacheSeconds: 30,
	}

	log.Printf("authOpts: %v\n%v\n", keys, values)
	//First, get backends
	backendsOk := false
	authOpts = make(map[string]string)
	for i := 0; i < authOptsNum; i++ {
		if keys[i] == "backends" {
			backends = strings.Split(strings.Replace(values[i], " ", "", -1), ",")
			if len(backends) > 0 {
				backendsCheck := true
				for _, backend := range backends {
					if _, ok := allowedBackends[backend]; !ok {
						backendsCheck = false
						log.Printf("backend not allowed: %s\n", backend)
					}
				}
				backendsOk = backendsCheck
			}
		} else if strings.Contains(keys[i], "cache") {
			//Get all cache options.
			/*if keys[i] == "cache_aut_seconds" {

			}*/

		} else {
			authOpts[keys[i]] = values[i]
		}
	}

	//Log and end program if backends are wrong
	if !backendsOk {
		log.Fatal("\nbackends error\n")
	}

	log.Printf("authOpts are: %v\n", authOpts)

	//Initialize backends
	for _, bename := range backends {
		var beIface Backend
		var bErr error

		if bename == "postgres" {
			beIface, bErr = bes.NewPostgres(authOpts)
			commonData.Postgres = beIface.(bes.Postgres)
		} else if bename == "jwt" {
			beIface, bErr = bes.NewJWT(authOpts)
			commonData.Jwt = beIface.(bes.JWT)
		} else if bename == "files" {
			beIface, bErr = bes.NewFiles(authOpts)
			commonData.Files = beIface.(bes.Files)
		}

		if bErr != nil {
			log.Printf("Backend register error: couldn't initialize %s backend with error %s.\n", bename, bErr)
		} else {
			log.Printf("Backend registered: %s\n", beIface.GetName())
		}

	}

}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password string) bool {

	//Loop through backends checking for user.

	authenticated := false

	for _, bename := range backends {

		var backend Backend

		if bename == "postgres" {
			backend = commonData.Postgres
		} else if bename == "jwt" {
			backend = commonData.Jwt
		} else if bename == "files" {
			backend = commonData.Files
		}

		if backend.GetUser(username, password) {
			authenticated = true
			log.Printf("user %s authenticated with backend %s\n", username, backend.GetName())
			break
		}
	}

	return authenticated
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) bool {

	aclCheck := false

	//Check superusers first

	for _, bename := range backends {

		var backend Backend

		if bename == "postgres" {
			backend = commonData.Postgres
		} else if bename == "jwt" {
			backend = commonData.Jwt
		} else if bename == "files" {
			backend = commonData.Files
		}

		fmt.Printf("Superuser check with backend %s\n", backend.GetName())
		if backend.GetSuperuser(username) {
			log.Printf("superuser %s acl authenticated with backend %s\n", username, backend.GetName())
			aclCheck = true
			break
		}
	}

	if !aclCheck {
		for _, bename := range backends {

			var backend Backend

			if bename == "postgres" {
				backend = commonData.Postgres
			} else if bename == "jwt" {
				backend = commonData.Jwt
			} else if bename == "files" {
				backend = commonData.Files
			}

			fmt.Printf("Acl check with backend %s\n", backend.GetName())
			if backend.CheckAcl(username, topic, clientid, int32(acc)) {
				log.Printf("user %s acl authenticated with backend %s\n", username, backend.GetName())
				aclCheck = true
				break
			}
		}
	}

	return aclCheck
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

func main() {}
