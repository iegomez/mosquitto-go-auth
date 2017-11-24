package main

import "C"

import (
	"github.com/go-redis/redis"
	"log"
	"strings"
	"strconv"
)

type Backend interface {
	GetUser(username, password string) bool
	GetSuperuser(username string) bool
	CheckAcl(username, topic, clientId string, acc int32) bool
}

type CommonData struct {
	Backends         []Backend
	Superusers       []string
	AclCacheSeconds  int32
	AuthCacheSeconds int32
	Redis            *redis.Client

	/*
		time_t acl_cacheseconds;
		struct cacheentry *aclcache;
		time_t auth_cacheseconds;
		struct cacheentry *authcache;
	*/
}

//Cache stores necessary values for Redis cache
type Cache struct {
	Host 		string
	Port 		string
	Password 	string
	DB 			string
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
var common Common

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int) {

	//Initialize Cache with default values
	cache = Cache{
		Host:		"localhost",
		Port:		"6379",
		Password:	"",
		DB:			"0",
	}

	commonBackends := make([]Backend, len(allowedBackends), len(allowedBackends))
	superusers := make([]string, 10, 10)

	//Initialize common struct with default and given values
	common = Common{
		Backends: commonBackends,
		Superusers: superusers,
		AclCacheSeconds:	30,
		AuthCacheSeconds:	30,
	}

	log.Printf("authOpts: %v\n%v\n", keys, values)
	//First, get backends
	backendsOk := false
	authOpts = make(map[string]string)
	for i := 0; i < authOptsNum; i++ {
		if keys[i] == "backends" {
			backends = strings.Split(strings.Replace(keys[i], " ", "", -1), ",")
			if len(backends) > 0 {
				backendsCheck := true
				for backend := range backends {
					if _, ok := allowedBackends[backend]; !ok {
						backendsCheck = false
					}
				}
				backendsOk = backendsCheck
			}
		} else if strings.Contains(keys[i], "cache") {
			//Get all cache options.
			if keys[i] == "cache_aut_seconds" {
				
			}
		}
		else {
			authOpts[keys[i]] = values[i]
		}
	}

	//Log and end program if backends are wrong
	if !backendsOk {
		log.Fatal("backends error")
	}

	log.Printf("authOpts are: %v\n", authOpts)

}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password string) bool {
	return true
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) bool {
	return true
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

func main() {}
