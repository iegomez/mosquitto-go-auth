package main

import "C"

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	bes "github.com/iegomez/mosquitto-go-auth/backends"
	"github.com/iegomez/mosquitto-go-auth/cache"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
)

type AuthPlugin struct {
	backends   *bes.Backends
	useCache   bool
	logLevel   log.Level
	logDest    string
	logFile    string
	ctx        context.Context
	cache      cache.Store
	hasher     hashing.HashComparer
	retryCount int
}

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
	AuthError    = 2
)

var authOpts map[string]string //Options passed by mosquitto.
var authPlugin AuthPlugin      //General struct with options and conf.

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int, version string) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	//Initialize auth plugin struct with default and given values.
	authPlugin = AuthPlugin{
		logLevel: log.InfoLevel,
		ctx:      context.Background(),
	}

	authOpts = make(map[string]string)
	for i := 0; i < authOptsNum; i++ {
		authOpts[keys[i]] = values[i]
	}

	if retryCount, ok := authOpts["retry_count"]; ok {
		retry, err := strconv.ParseInt(retryCount, 10, 64)
		if err == nil {
			authPlugin.retryCount = int(retry)
		} else {
			log.Warningf("couldn't parse retryCount (err: %s), defaulting to 0", err)
		}
	}

	//Check if log level is given. Set level if any valid option is given.
	if logLevel, ok := authOpts["log_level"]; ok {
		logLevel = strings.Replace(logLevel, " ", "", -1)
		switch logLevel {
		case "debug":
			authPlugin.logLevel = log.DebugLevel
		case "info":
			authPlugin.logLevel = log.InfoLevel
		case "warn":
			authPlugin.logLevel = log.WarnLevel
		case "error":
			authPlugin.logLevel = log.ErrorLevel
		case "fatal":
			authPlugin.logLevel = log.FatalLevel
		case "panic":
			authPlugin.logLevel = log.PanicLevel
		default:
			log.Info("log_level unkwown, using default info level")
		}
	}

	if logDest, ok := authOpts["log_dest"]; ok {
		switch logDest {
		case "stdout":
			log.SetOutput(os.Stdout)
		case "file":
			if logFile, ok := authOpts["log_file"]; ok {
				file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					log.SetOutput(file)
				} else {
					log.Errorf("failed to log to file, using default stderr: %s", err)
				}
			}
		default:
			log.Info("log_dest unknown, using default stderr")
		}
	}

	var err error

	authPlugin.backends, err = bes.Initialize(authOpts, authPlugin.logLevel, version)
	if err != nil {
		log.Fatalf("error initializing backends: %s", err)
	}

	if cache, ok := authOpts["cache"]; ok && strings.Replace(cache, " ", "", -1) == "true" {
		log.Info("redisCache activated")
		authPlugin.useCache = true
	} else {
		log.Info("No cache set.")
		authPlugin.useCache = false
	}

	if authPlugin.useCache {
		setCache(authOpts)
	}
}

func setCache(authOpts map[string]string) {

	var aclCacheSeconds int64 = 30
	var authCacheSeconds int64 = 30
	var authJitterSeconds int64 = 0
	var aclJitterSeconds int64 = 0

	if authCacheSec, ok := authOpts["auth_cache_seconds"]; ok {
		authSec, err := strconv.ParseInt(authCacheSec, 10, 64)
		if err == nil {
			authCacheSeconds = authSec
		} else {
			log.Warningf("couldn't parse authCacheSeconds (err: %s), defaulting to %d", err, authCacheSeconds)
		}
	}

	if authJitterSec, ok := authOpts["auth_jitter_seconds"]; ok {
		authSec, err := strconv.ParseInt(authJitterSec, 10, 64)
		if err == nil {
			authJitterSeconds = authSec
		} else {
			log.Warningf("couldn't parse authJitterSeconds (err: %s), defaulting to %d", err, authJitterSeconds)
		}
	}

	if authJitterSeconds > authCacheSeconds {
		authJitterSeconds = authCacheSeconds
		log.Warningf("authJitterSeconds is larger than authCacheSeconds, defaulting to %d", authJitterSeconds)
	}

	if aclCacheSec, ok := authOpts["acl_cache_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclCacheSec, 10, 64)
		if err == nil {
			aclCacheSeconds = aclSec
		} else {
			log.Warningf("couldn't parse aclCacheSeconds (err: %s), defaulting to %d", err, aclCacheSeconds)
		}
	}

	if aclJitterSec, ok := authOpts["acl_jitter_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclJitterSec, 10, 64)
		if err == nil {
			aclJitterSeconds = aclSec
		} else {
			log.Warningf("couldn't parse aclJitterSeconds (err: %s), defaulting to %d", err, aclJitterSeconds)
		}
	}

	if aclJitterSeconds > aclCacheSeconds {
		aclJitterSeconds = aclCacheSeconds
		log.Warningf("aclJitterSeconds is larger than aclCacheSeconds, defaulting to %d", aclJitterSeconds)
	}

	reset := false
	if cacheReset, ok := authOpts["cache_reset"]; ok && cacheReset == "true" {
		reset = true
	}

	refreshExpiration := false
	if refresh, ok := authOpts["cache_refresh"]; ok && refresh == "true" {
		refreshExpiration = true
	}

	switch authOpts["cache_type"] {
	case "redis":
		host := "localhost"
		port := "6379"
		db := 3
		password := ""
		cluster := false

		if authOpts["cache_mode"] == "true" {
			cluster = true
		}

		if cachePassword, ok := authOpts["cache_password"]; ok {
			password = cachePassword
		}

		if cluster {

			addressesOpt := authOpts["redis_cluster_addresses"]
			if addressesOpt == "" {
				log.Errorln("cache Redis cluster addresses missing, defaulting to no cache.")
				authPlugin.useCache = false
				return
			}

			// Take the given addresses and trim spaces from them.
			addresses := strings.Split(addressesOpt, ",")
			for i := 0; i < len(addresses); i++ {
				addresses[i] = strings.TrimSpace(addresses[i])
			}

			authPlugin.cache = cache.NewRedisClusterStore(
				password,
				addresses,
				time.Duration(authCacheSeconds)*time.Second,
				time.Duration(aclCacheSeconds)*time.Second,
				time.Duration(authJitterSeconds)*time.Second,
				time.Duration(aclJitterSeconds)*time.Second,
				refreshExpiration,
			)

		} else {
			if cacheHost, ok := authOpts["cache_host"]; ok {
				host = cacheHost
			}

			if cachePort, ok := authOpts["cache_port"]; ok {
				port = cachePort
			}

			if cacheDB, ok := authOpts["cache_db"]; ok {
				parsedDB, err := strconv.ParseInt(cacheDB, 10, 32)
				if err == nil {
					db = int(parsedDB)
				} else {
					log.Warningf("couldn't parse cache db (err: %s), defaulting to %d", err, db)
				}
			}

			authPlugin.cache = cache.NewSingleRedisStore(
				host,
				port,
				password,
				db,
				time.Duration(authCacheSeconds)*time.Second,
				time.Duration(aclCacheSeconds)*time.Second,
				time.Duration(authJitterSeconds)*time.Second,
				time.Duration(aclJitterSeconds)*time.Second,
				refreshExpiration,
			)
		}

	default:
		authPlugin.cache = cache.NewGoStore(
			time.Duration(authCacheSeconds)*time.Second,
			time.Duration(aclCacheSeconds)*time.Second,
			time.Duration(authJitterSeconds)*time.Second,
			time.Duration(aclJitterSeconds)*time.Second,
			refreshExpiration,
		)
	}

	if !authPlugin.cache.Connect(authPlugin.ctx, reset) {
		authPlugin.cache = nil
		authPlugin.useCache = false
		log.Infoln("couldn't start cache, defaulting to no cache")
	}

}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password, clientid string) uint8 {
	var ok bool
	var err error

	for try := 0; try <= authPlugin.retryCount; try++ {
		ok, err = authUnpwdCheck(username, password, clientid)
		if err == nil {
			break
		}
	}

	if err != nil {
		log.Error(err)
		return AuthError
	}

	if ok {
		return AuthGranted
	}

	return AuthRejected
}

func authUnpwdCheck(username, password, clientid string) (bool, error) {
	var authenticated bool
	var cached bool
	var granted bool
	var err error
	if authPlugin.useCache {
		log.Debugf("checking auth cache for %s", username)
		cached, granted = authPlugin.cache.CheckAuthRecord(authPlugin.ctx, username, password)
		if cached {
			log.Debugf("found in cache: %s", username)
			return granted, nil
		}
	}

	authenticated, err = authPlugin.backends.AuthUnpwdCheck(username, password, clientid)

	if authPlugin.useCache && err == nil {
		authGranted := "false"
		if authenticated {
			authGranted = "true"
		}
		log.Debugf("setting auth cache for %s", username)
		if setAuthErr := authPlugin.cache.SetAuthRecord(authPlugin.ctx, username, password, authGranted); setAuthErr != nil {
			log.Errorf("set auth cache: %s", setAuthErr)
			return false, setAuthErr
		}
	}
	return authenticated, err
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) uint8 {
	var ok bool
	var err error

	for try := 0; try <= authPlugin.retryCount; try++ {
		ok, err = authAclCheck(clientid, username, topic, acc)
		if err == nil {
			break
		}
	}

	if err != nil {
		log.Error(err)
		return AuthError
	}

	if ok {
		return AuthGranted
	}

	return AuthRejected
}

func authAclCheck(clientid, username, topic string, acc int) (bool, error) {
	var aclCheck bool
	var cached bool
	var granted bool
	var err error
	if authPlugin.useCache {
		log.Debugf("checking acl cache for %s", username)
		cached, granted = authPlugin.cache.CheckACLRecord(authPlugin.ctx, username, topic, clientid, acc)
		if cached {
			log.Debugf("found in cache: %s", username)
			return granted, nil
		}
	}

	aclCheck, err = authPlugin.backends.AuthAclCheck(clientid, username, topic, acc)

	if authPlugin.useCache && err == nil {
		authGranted := "false"
		if aclCheck {
			authGranted = "true"
		}
		log.Debugf("setting acl cache (granted = %s) for %s", authGranted, username)
		if setACLErr := authPlugin.cache.SetACLRecord(authPlugin.ctx, username, topic, clientid, acc, authGranted); setACLErr != nil {
			log.Errorf("set acl cache: %s", setACLErr)
			return false, setACLErr
		}
	}

	log.Debugf("Acl is %t for user %s", aclCheck, username)
	return aclCheck, err
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//export AuthPluginCleanup
func AuthPluginCleanup() {
	log.Info("Cleaning up plugin")
	//If cache is set, close cache connection.
	if authPlugin.cache != nil {
		authPlugin.cache.Close()
	}

	authPlugin.backends.Halt()
}

func main() {}
