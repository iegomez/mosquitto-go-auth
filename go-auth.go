package main

import "C"

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	b64 "encoding/base64"

	goredis "github.com/go-redis/redis"
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
	Redis            bes.Redis
	Superusers       []string
	AclCacheSeconds  int64
	AuthCacheSeconds int64
	UseCache         bool
	RedisCache       *goredis.Client
}

//Cache stores necessary values for Redis cache
type Cache struct {
	Host     string
	Port     string
	Password string
	DB       int32
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
		DB:       0,
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
		} else {
			authOpts[keys[i]] = values[i]
		}
	}

	//Log and end program if backends are wrong
	if !backendsOk {
		log.Fatal("\nbackends error\n")
	}

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
		} else if bename == "redis" {
			beIface, bErr = bes.NewRedis(authOpts)
			commonData.Redis = beIface.(bes.Redis)
		}

		if bErr != nil {
			log.Printf("Backend register error: couldn't initialize %s backend with error %s.\n", bename, bErr)
		} else {
			log.Printf("Backend registered: %s\n", beIface.GetName())
		}

	}

	if cache, ok := authOpts["cache"]; ok && cache == "true" {
		log.Println("Cache set")
		commonData.UseCache = true
	} else {
		log.Printf("No cache, got %s", cache)
		commonData.UseCache = false
	}

	if commonData.UseCache {
		if cacheHost, ok := authOpts["cache_host"]; ok {
			cache.Host = cacheHost
		}

		if cachePort, ok := authOpts["cache_port"]; ok {
			cache.Port = cachePort
		}

		if cachePassword, ok := authOpts["cache_password"]; ok {
			cache.Password = cachePassword
		}

		if cacheDB, ok := authOpts["cache_db"]; ok {
			db, err := strconv.ParseInt(cacheDB, 10, 32)
			if err != nil {
				cache.DB = int32(db)
			}
		}

		if authCacheSec, ok := authOpts["auth_cache_seconds"]; ok {
			authSec, err := strconv.ParseInt(authCacheSec, 10, 64)
			if err != nil {
				commonData.AuthCacheSeconds = authSec
			}

		}

		if aclCacheSec, ok := authOpts["acl_cache_seconds"]; ok {
			aclSec, err := strconv.ParseInt(aclCacheSec, 10, 64)
			if err != nil {
				commonData.AclCacheSeconds = aclSec
			}

		}

		addr := fmt.Sprintf("%s:%s", cache.Host, cache.Port)

		//If cache is on, try to start redis.
		goredisClient := goredis.NewClient(&goredis.Options{
			Addr:     addr,
			Password: cache.Password, // no password set
			DB:       int(cache.DB),  // use default DB
		})

		_, err := goredisClient.Ping().Result()
		if err != nil {
			log.Printf("couldn't start Redis, defaulting to no cache. error: %s\n", err)
			commonData.UseCache = false
		} else {
			commonData.RedisCache = goredisClient
			log.Printf("started redis client")
		}

	}

}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password string) bool {

	//Loop through backends checking for user.

	authenticated := false
	var cached = false
	var granted = false
	if commonData.UseCache {
		log.Printf("checking auth cache for %s\n", username)
		cached, granted = CheckAuthCache(username, password)
		if cached {
			log.Printf("found in cache: %s\n", username)
			return granted
		}
	}

	for _, bename := range backends {

		var backend Backend

		if bename == "postgres" {
			backend = commonData.Postgres
		} else if bename == "jwt" {
			backend = commonData.Jwt
		} else if bename == "files" {
			backend = commonData.Files
		} else if bename == "redis" {
			backend = commonData.Redis
		}

		if backend.GetUser(username, password) {
			authenticated = true
			log.Printf("user %s authenticated with backend %s\n", username, backend.GetName())
			break
		}
	}

	if commonData.UseCache {
		authGranted := "false"
		if authenticated {
			authGranted = "true"
		}
		log.Printf("setting auth cache for %s\n", username)
		SetAuthCache(username, password, authGranted)
	}

	return authenticated
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) bool {

	aclCheck := false
	var cached = false
	var granted = false
	if commonData.UseCache {
		log.Printf("checking acl cache for %s\n", username)
		cached, granted = CheckAclCache(username, topic, clientid, acc)
		if cached {
			log.Printf("found in cache: %s\n", username)
			return granted
		}
	}

	//Check superusers first

	for _, bename := range backends {

		var backend Backend

		if bename == "postgres" {
			backend = commonData.Postgres
		} else if bename == "jwt" {
			backend = commonData.Jwt
		} else if bename == "files" {
			backend = commonData.Files
		} else if bename == "redis" {
			backend = commonData.Redis
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
			} else if bename == "redis" {
				backend = commonData.Redis
			}

			fmt.Printf("Acl check with backend %s\n", backend.GetName())
			if backend.CheckAcl(username, topic, clientid, int32(acc)) {
				log.Printf("user %s acl authenticated with backend %s\n", username, backend.GetName())
				aclCheck = true
				break
			}
		}
	}

	if commonData.UseCache {
		authGranted := "false"
		if aclCheck {
			authGranted = "true"
		}
		log.Printf("setting acl cache for %s\n", username)
		SetAclCache(username, topic, clientid, acc, authGranted)
	}

	return aclCheck
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//CheckAuthCache checks if the username/password pair is present in the cache. Return if it's present and, if so, if it was granted privileges.
func CheckAuthCache(username, password string) (bool, bool) {
	pair := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("auth%s%s", username, password)))
	val, err := commonData.RedisCache.Get(pair).Result()
	if err != nil {
		return false, false
	}
	//refresh expiration
	commonData.RedisCache.Expire(pair, time.Duration(commonData.AuthCacheSeconds)*time.Second)
	if val == "true" {
		return true, true
	}
	return true, false
}

//SetAuthCache sets a pair, granted option and expiration time.
func SetAuthCache(username, password string, granted string) error {
	pair := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("auth%s%s", username, password)))
	err := commonData.RedisCache.Set(pair, granted, time.Duration(commonData.AuthCacheSeconds)*time.Second).Err()
	if err != nil {
		return err
	}

	return nil
}

//CheckAclCache checks if the username/topic/clientid/acc mix is present in the cache. Return if it's present and, if so, if it was granted privileges.
func CheckAclCache(username, topic, clientid string, acc int) (bool, bool) {
	pair := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("acl%s%s%s%d", username, topic, clientid, acc)))
	val, err := commonData.RedisCache.Get(pair).Result()
	if err != nil {
		return false, false
	}
	//refresh expiration
	commonData.RedisCache.Expire(pair, time.Duration(commonData.AclCacheSeconds)*time.Second)
	if val == "true" {
		return true, true
	}
	return true, false
}

//SetAclCache sets a mix, granted option and expiration time.
func SetAclCache(username, topic, clientid string, acc int, granted string) error {
	pair := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("acl%s%s%s%d", username, topic, clientid, acc)))
	err := commonData.RedisCache.Set(pair, granted, time.Duration(commonData.AclCacheSeconds)*time.Second).Err()
	if err != nil {
		return err
	}

	return nil
}

func main() {}
