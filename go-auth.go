package main

import "C"

import (
	"context"
	"os"
	"plugin"
	"strconv"
	"strings"
	"time"

	bes "github.com/iegomez/mosquitto-go-auth/backends"
	"github.com/iegomez/mosquitto-go-auth/cache"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
)

type Backend interface {
	GetUser(username, password, clientid string) (bool, error)
	GetSuperuser(username string) (bool, error)
	CheckAcl(username, topic, clientId string, acc int32) (bool, error)
	GetName() string
	Halt()
}

type AuthPlugin struct {
	backends                 map[string]Backend
	customPlugin             *plugin.Plugin
	PInit                    func(map[string]string, log.Level) error
	customPluginGetName      func() string
	customPluginGetUser      func(username, password, clientid string) (bool, error)
	customPluginGetSuperuser func(username string) (bool, error)
	customPluginCheckAcl     func(username, topic, clientid string, acc int) (bool, error)
	customPluginHalt         func()
	useCache                 bool
	checkPrefix              bool
	prefixes                 map[string]string
	logLevel                 log.Level
	logDest                  string
	logFile                  string
	disableSuperuser         bool
	ctx                      context.Context
	cache                    cache.Store
	hasher                   hashing.HashComparer
}

const (
	//backends
	postgresBackend = "postgres"
	jwtBackend      = "jwt"
	redisBackend    = "redis"
	httpBackend     = "http"
	filesBackend    = "files"
	mysqlBackend    = "mysql"
	sqliteBackend   = "sqlite"
	mongoBackend    = "mongo"
	pluginBackend   = "plugin"
	grpcBackend     = "grpc"
	jsBackend       = "js"

	AuthRejected = 0
	AuthGranted  = 1
	AuthError    = 2
)

// Serves s a check for allowed backends and a map from backend to expected opts prefix.
var allowedBackendsOptsPrefix = map[string]string{
	postgresBackend: "pg",
	jwtBackend:      "jwt",
	redisBackend:    "redis",
	httpBackend:     "http",
	filesBackend:    "files",
	mysqlBackend:    "mysql",
	sqliteBackend:   "sqlite",
	mongoBackend:    "mongo",
	pluginBackend:   "plugin",
	grpcBackend:     "grpc",
	jsBackend:       "js",
}

var backends []string          //List of selected backends.
var authOpts map[string]string //Options passed by mosquitto.
var authPlugin AuthPlugin      //General struct with options and conf.

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	cmBackends := make(map[string]Backend)

	//Initialize auth plugin struct with default and given values.
	authPlugin = AuthPlugin{
		checkPrefix: false,
		prefixes:    make(map[string]string),
		logLevel:    log.InfoLevel,
		ctx:         context.Background(),
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
					if _, ok := allowedBackendsOptsPrefix[backend]; !ok {
						backendsCheck = false
						log.Errorf("backend not allowed: %s", backend)
					}
				}
				backendsOk = backendsCheck
			}
		}
		// Always set backends option so backends may know if they are running solo or not.
		authOpts[keys[i]] = values[i]
	}

	//Log and end program if backends are wrong
	if !backendsOk {
		log.Fatal("backends error")
	}

	//Disable superusers for all backends if option is set.
	if authOpts["disable_superuser"] == "true" {
		authPlugin.disableSuperuser = true
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

	//Initialize backends
	for _, bename := range backends {
		var beIface Backend
		var err error
		if bename == pluginBackend {
			plug, err := plugin.Open(authOpts["plugin_path"])
			if err != nil {
				log.Errorf("Could not init custom plugin: %s", err)
				authPlugin.customPlugin = nil
			} else {
				authPlugin.customPlugin = plug

				plInit, err := authPlugin.customPlugin.Lookup("Init")

				if err != nil {
					log.Errorf("Couldn't find func Init in plugin: %s", err)
					authPlugin.customPlugin = nil
					continue
				}

				initFunc := plInit.(func(authOpts map[string]string, logLevel log.Level) error)

				err = initFunc(authOpts, authPlugin.logLevel)
				if err != nil {
					log.Errorf("Couldn't init plugin: %s", err)
					authPlugin.customPlugin = nil
					continue
				}

				authPlugin.PInit = initFunc

				plName, err := authPlugin.customPlugin.Lookup("GetName")

				if err != nil {
					log.Errorf("Couldn't find func GetName in plugin: %s", err)
					authPlugin.customPlugin = nil
					continue
				}

				nameFunc := plName.(func() string)
				authPlugin.customPluginGetName = nameFunc

				plGetUser, err := authPlugin.customPlugin.Lookup("GetUser")

				if err != nil {
					log.Errorf("couldn't find func GetUser in plugin: %s", err)
					authPlugin.customPlugin = nil
					continue
				}

				getUserFunc, ok := plGetUser.(func(username, password, clientid string) (bool, error))
				if !ok {
					tmp := plGetUser.(func(username, password, clientid string) bool)
					getUserFunc = func(username, password, clientid string) (bool, error) {
						return tmp(username, password, clientid), nil
					}
				}
				authPlugin.customPluginGetUser = getUserFunc

				plGetSuperuser, err := authPlugin.customPlugin.Lookup("GetSuperuser")

				if err != nil {
					log.Errorf("couldn't find func GetSuperuser in plugin: %s", err)
					authPlugin.customPlugin = nil
					continue
				}

				getSuperuserFunc, ok := plGetSuperuser.(func(username string) (bool, error))
				if !ok {
					tmp := plGetSuperuser.(func(username string) bool)
					getSuperuserFunc = func(username string) (bool, error) {
						return tmp(username), nil
					}
				}
				authPlugin.customPluginGetSuperuser = getSuperuserFunc

				plCheckAcl, err := authPlugin.customPlugin.Lookup("CheckAcl")

				if err != nil {
					log.Errorf("couldn't find func CheckAcl in plugin: %s", err)
					authPlugin.customPlugin = nil
					continue
				}

				checkAclFunc, ok := plCheckAcl.(func(username, topic, clientid string, acc int) (bool, error))
				if !ok {
					tmp := plCheckAcl.(func(username, topic, clientid string, acc int) bool)
					checkAclFunc = func(username, topic, clientid string, acc int) (bool, error) {
						return tmp(username, topic, clientid, acc), nil
					}
				}
				authPlugin.customPluginCheckAcl = checkAclFunc

				plHalt, err := authPlugin.customPlugin.Lookup("Halt")

				if err != nil {
					log.Errorf("Couldn't find func Halt in plugin: %s", err)
					authPlugin.customPlugin = nil
					continue
				}

				haltFunc := plHalt.(func())
				authPlugin.customPluginHalt = haltFunc

				log.Infof("Backend registered: %s", authPlugin.customPluginGetName())

			}
		} else {
			hasher := hashing.NewHasher(authOpts, allowedBackendsOptsPrefix[bename])
			switch bename {
			case postgresBackend:
				beIface, err = bes.NewPostgres(authOpts, authPlugin.logLevel, hasher)
				if err != nil {
					log.Fatalf("backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("backend registered: %s", beIface.GetName())
					cmBackends[postgresBackend] = beIface.(bes.Postgres)
				}
			case jwtBackend:
				beIface, err = bes.NewJWT(authOpts, authPlugin.logLevel, hasher)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[jwtBackend] = beIface.(*bes.JWT)
				}
			case filesBackend:
				beIface, err = bes.NewFiles(authOpts, authPlugin.logLevel, hasher)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[filesBackend] = beIface.(bes.Files)
				}
			case redisBackend:
				beIface, err = bes.NewRedis(authOpts, authPlugin.logLevel, hasher)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[redisBackend] = beIface.(bes.Redis)
				}
			case mysqlBackend:
				beIface, err = bes.NewMysql(authOpts, authPlugin.logLevel, hasher)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[mysqlBackend] = beIface.(bes.Mysql)
				}
			case httpBackend:
				beIface, err = bes.NewHTTP(authOpts, authPlugin.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[httpBackend] = beIface.(bes.HTTP)
				}
			case sqliteBackend:
				beIface, err = bes.NewSqlite(authOpts, authPlugin.logLevel, hasher)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[sqliteBackend] = beIface.(bes.Sqlite)
				}
			case mongoBackend:
				beIface, err = bes.NewMongo(authOpts, authPlugin.logLevel, hasher)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[mongoBackend] = beIface.(bes.Mongo)
				}
			case grpcBackend:
				beIface, err = bes.NewGRPC(authOpts, authPlugin.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[grpcBackend] = beIface.(bes.GRPC)
				}
			case jsBackend:
				beIface, err = bes.NewJavascript(authOpts, authPlugin.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[jsBackend] = beIface.(*bes.Javascript)
				}
			}
		}
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

	if checkPrefix, ok := authOpts["check_prefix"]; ok && strings.Replace(checkPrefix, " ", "", -1) == "true" {
		//Check that backends match prefixes.
		if prefixesStr, ok := authOpts["prefixes"]; ok {
			prefixes := strings.Split(strings.Replace(prefixesStr, " ", "", -1), ",")
			if len(prefixes) == len(backends) {
				//Set prefixes
				for i, backend := range backends {
					authPlugin.prefixes[prefixes[i]] = backend
				}
				log.Infof("prefixes enabled for backends %s with prefixes %s.", authOpts["backends"], authOpts["prefixes"])
				authPlugin.checkPrefix = true
			} else {
				log.Errorf("Error: got %d backends and %d prefixes, defaulting to prefixes disabled.", len(backends), len(prefixes))
				authPlugin.checkPrefix = false
			}

		} else {
			log.Warn("Error: prefixes enabled but no options given, defaulting to prefixes disabled.")
			authPlugin.checkPrefix = false
		}
	} else {
		authPlugin.checkPrefix = false
	}
	authPlugin.backends = cmBackends
}

func setCache(authOpts map[string]string) {

	var aclCacheSeconds int64 = 30
	var authCacheSeconds int64 = 30

	if authCacheSec, ok := authOpts["auth_cache_seconds"]; ok {
		authSec, err := strconv.ParseInt(authCacheSec, 10, 64)
		if err == nil {
			authCacheSeconds = authSec
		} else {
			log.Warningf("couldn't parse authCacheSeconds (err: %s), defaulting to %d", err, authCacheSeconds)
		}
	}

	if aclCacheSec, ok := authOpts["acl_cache_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclCacheSec, 10, 64)
		if err == nil {
			aclCacheSeconds = aclSec
		} else {
			log.Warningf("couldn't parse aclCacheSeconds (err: %s), defaulting to %d", err, aclCacheSeconds)
		}
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
				refreshExpiration,
			)
		}

	default:
		authPlugin.cache = cache.NewGoStore(
			time.Duration(authCacheSeconds)*time.Second,
			time.Duration(aclCacheSeconds)*time.Second,
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
	ok, err := authUnpwdCheck(username, password, clientid)
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
	var firstError error
	if authPlugin.useCache {
		log.Debugf("checking auth cache for %s", username)
		cached, granted = authPlugin.cache.CheckAuthRecord(authPlugin.ctx, username, password)
		if cached {
			log.Debugf("found in cache: %s", username)
			return granted, nil
		}
	}

	//If prefixes are enabled, check if username has a valid prefix and use the correct backend if so.
	if authPlugin.checkPrefix {
		validPrefix, bename := CheckPrefix(username)
		if validPrefix {
			if bename == pluginBackend {
				authenticated, firstError = CheckPluginAuth(username, password, clientid)
			} else {
				// If the backend is JWT and the token was prefixed, then strip the token. If the token was passed without a prefix it will be handled in the common case.
				if bename == jwtBackend {
					prefix := getPrefixForBackend(bename)
					username = strings.TrimPrefix(username, prefix+"_")
				}
				var backend = authPlugin.backends[bename]

				authenticated, firstError = backend.GetUser(username, password, clientid)
				if authenticated && firstError == nil {
					log.Debugf("user %s authenticated with backend %s", username, backend.GetName())
				}
			}
		} else {
			//If there's no valid prefix, check all backends.
			authenticated, firstError = CheckBackendsAuth(username, password, clientid)
			//If not authenticated, check for a present plugin
			if !authenticated {
				if ok, err := CheckPluginAuth(username, password, clientid); ok && err == nil {
					authenticated = true
					firstError = nil
				} else if err != nil && firstError == nil {
					firstError = err
				}
			}
		}
	} else {
		authenticated, firstError = CheckBackendsAuth(username, password, clientid)
		//If not authenticated, check for a present plugin
		if !authenticated {
			if ok, err := CheckPluginAuth(username, password, clientid); ok && err == nil {
				authenticated = true
				firstError = nil
			} else if err != nil && firstError == nil {
				firstError = err
			}
		}
	}

	if authPlugin.useCache && firstError == nil {
		authGranted := "false"
		if authenticated {
			authGranted = "true"
		}
		log.Debugf("setting auth cache for %s", username)
		if err := authPlugin.cache.SetAuthRecord(authPlugin.ctx, username, password, authGranted); err != nil {
			log.Errorf("set auth cache: %s", err)
			return false, err
		}
	}
	return authenticated, firstError
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) uint8 {
	ok, err := authAclCheck(clientid, username, topic, acc)
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
	var firstError error
	if authPlugin.useCache {
		log.Debugf("checking acl cache for %s", username)
		cached, granted = authPlugin.cache.CheckACLRecord(authPlugin.ctx, username, topic, clientid, acc)
		if cached {
			log.Debugf("found in cache: %s", username)
			return granted, nil
		}
	}
	//If prefixes are enabled, check if username has a valid prefix and use the correct backend if so.
	//Else, check all backends.
	if authPlugin.checkPrefix {
		validPrefix, bename := CheckPrefix(username)
		if validPrefix {
			if bename == pluginBackend {
				aclCheck, firstError = CheckPluginAcl(username, topic, clientid, acc)
			} else {
				// If the backend is JWT and the token was prefixed, then strip the token. If the token was passed without a prefix then it be handled in the common case.
				if bename == jwtBackend {
					prefix := getPrefixForBackend(bename)
					username = strings.TrimPrefix(username, prefix+"_")
				}
				var backend = authPlugin.backends[bename]
				log.Debugf("Superuser check with backend %s", backend.GetName())
				// Short circuit checks when superusers are disabled.
				if !authPlugin.disableSuperuser {
					aclCheck, firstError = backend.GetSuperuser(username)

					if aclCheck && firstError == nil {
						log.Debugf("superuser %s acl authenticated with backend %s", username, backend.GetName())
					}
				}
				//If not superuser, check acl.
				if !aclCheck {
					log.Debugf("Acl check with backend %s", backend.GetName())
					if ok, err := backend.CheckAcl(username, topic, clientid, int32(acc)); ok && err == nil {
						aclCheck = true
						log.Debugf("user %s acl authenticated with backend %s", username, backend.GetName())
					} else if err != nil && firstError == nil {
						firstError = err
					}
				}
			}
		} else {
			//If there's no valid prefix, check all backends.
			aclCheck, firstError = CheckBackendsAcl(username, topic, clientid, acc)
			//If acl hasn't passed, check for plugin.
			if !aclCheck {
				if ok, err := CheckPluginAcl(username, topic, clientid, acc); ok && err == nil {
					aclCheck = true
				} else if err != nil && firstError == nil {
					firstError = err
				}
			}
		}
	} else {
		aclCheck, firstError = CheckBackendsAcl(username, topic, clientid, acc)
		//If acl hasn't passed, check for plugin.
		if !aclCheck {
			if ok, err := CheckPluginAcl(username, topic, clientid, acc); ok && err == nil {
				aclCheck = true
			} else if err != nil && firstError == nil {
				firstError = err
			}
		}
	}

	if authPlugin.useCache && firstError == nil {
		authGranted := "false"
		if aclCheck {
			authGranted = "true"
		}
		log.Debugf("setting acl cache (granted = %s) for %s", authGranted, username)
		if err := authPlugin.cache.SetACLRecord(authPlugin.ctx, username, topic, clientid, acc, authGranted); err != nil {
			log.Errorf("set acl cache: %s", err)
			return false, err
		}
	}

	log.Debugf("Acl is %t for user %s", aclCheck, username)
	return aclCheck, firstError
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//checkPrefix checks if a username contains a valid prefix. If so, returns ok and the suitable backend name; else, !ok and empty string.
func CheckPrefix(username string) (bool, string) {
	if strings.Index(username, "_") > 0 {
		userPrefix := username[0:strings.Index(username, "_")]
		if prefix, ok := authPlugin.prefixes[userPrefix]; ok {
			log.Debugf("Found prefix for user %s, using backend %s.", username, prefix)
			return true, prefix
		}
	}
	return false, ""
}

//getPrefixForBackend retrieves the user provided prefix for a given backend.
func getPrefixForBackend(backend string) string {
	for k, v := range authPlugin.prefixes {
		if v == backend {
			return k
		}
	}
	return ""
}

//CheckBackendsAuth checks for all backends if a username is authenticated and sets the authenticated param.
func CheckBackendsAuth(username, password, clientid string) (bool, error) {
	var firstError error
	authenticated := false

	for _, bename := range backends {

		if bename == pluginBackend {
			continue
		}

		var backend = authPlugin.backends[bename]

		log.Debugf("checking user %s with backend %s", username, backend.GetName())

		if ok, err := backend.GetUser(username, password, clientid); ok && err == nil {
			authenticated = true
			log.Debugf("user %s authenticated with backend %s", username, backend.GetName())
			break
		} else if err != nil && firstError == nil {
			firstError = err
		}
	}

	// If authenticated is true, it means at least one backend didn't failed and
	// accepted the user. In this case trust this backend and clear the error.
	if authenticated {
		firstError = nil
	}

	return authenticated, firstError

}

//CheckBackendsAcl  checks for all backends if a username is superuser or has acl rights and sets the aclCheck param.
func CheckBackendsAcl(username, topic, clientid string, acc int) (bool, error) {
	//Check superusers first
	var firstError error
	aclCheck := false
	if !authPlugin.disableSuperuser {
		for _, bename := range backends {
			if bename == pluginBackend {
				continue
			}
			var backend = authPlugin.backends[bename]
			log.Debugf("Superuser check with backend %s", backend.GetName())
			if ok, err := backend.GetSuperuser(username); ok && err == nil {
				log.Debugf("superuser %s acl authenticated with backend %s", username, backend.GetName())
				aclCheck = true
				break
			} else if err != nil && firstError == nil {
				firstError = err
			}
		}
	}

	if !aclCheck {
		for _, bename := range backends {
			if bename == pluginBackend {
				continue
			}
			var backend = authPlugin.backends[bename]
			log.Debugf("Acl check with backend %s", backend.GetName())
			if ok, err := backend.CheckAcl(username, topic, clientid, int32(acc)); ok && err == nil {
				log.Debugf("user %s acl authenticated with backend %s", username, backend.GetName())
				aclCheck = true
				break
			} else if err != nil && firstError == nil {
				firstError = err
			}
		}
	}

	// If aclCheck is true, it means at least one backend didn't failed and
	// accepted the access. In this case trust this backend and clear the error.
	if aclCheck {
		firstError = nil
	}

	return aclCheck, firstError
}

//CheckPluginAuth checks that the plugin is not nil and returns the plugins auth response.
func CheckPluginAuth(username, password, clientid string) (bool, error) {
	if authPlugin.customPlugin == nil {
		return false, nil
	}
	return authPlugin.customPluginGetUser(username, password, clientid)
}

//CheckPluginAcl checks that the plugin is not nil and returns the superuser/acl response.
func CheckPluginAcl(username, topic, clientid string, acc int) (bool, error) {
	var aclCheck bool
	var err error
	if authPlugin.customPlugin == nil {
		return false, nil
	}
	//If superuser, authorize it unless superusers are disabled.
	if !authPlugin.disableSuperuser {
		aclCheck, err = authPlugin.customPluginGetSuperuser(username)
	}

	if !aclCheck && err == nil {
		//Check against the plugin's check acl function.
		aclCheck, err = authPlugin.customPluginCheckAcl(username, topic, clientid, acc)
	}

	return aclCheck, err
}

//export AuthPluginCleanup
func AuthPluginCleanup() {
	log.Info("Cleaning up plugin")
	//If cache is set, close cache connection.
	if authPlugin.cache != nil {
		authPlugin.cache.Close()
	}

	//Halt every registered backend.
	for _, v := range authPlugin.backends {
		v.Halt()
	}

	if authPlugin.customPlugin != nil {
		authPlugin.customPluginHalt()
	}
}

func main() {}
