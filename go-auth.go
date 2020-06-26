package main

import "C"

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"os"
	"plugin"
	"strconv"
	"strings"
	"time"

	goredis "github.com/go-redis/redis/v8"
	bes "github.com/iegomez/mosquitto-go-auth/backends"
	log "github.com/sirupsen/logrus"
)

type Backend interface {
	GetUser(username, password, clientid string) bool
	GetSuperuser(username string) bool
	CheckAcl(username, topic, clientId string, acc int32) bool
	GetName() string
	Halt()
}

type AuthPlugin struct {
	backends                 map[string]Backend
	customPlugin             *plugin.Plugin
	PInit                    func(map[string]string, log.Level) error
	customPluginGetName      func() string
	customPluginGetUser      func(username, password string) bool
	customPluginGetSuperuser func(username string) bool
	customPluginCheckAcl     func(username, topic, clientid string, acc int) bool
	customPluginHalt         func()
	aclCacheSeconds          int64
	authCacheSeconds         int64
	useCache                 bool
	redisCache               bes.RedisClient
	checkPrefix              bool
	prefixes                 map[string]string
	logLevel                 log.Level
	logDest                  string
	logFile                  string
	disableSuperuser         bool
	ctx                      context.Context
}

//Cache stores necessary values for Redis cache
type Cache struct {
	host     string
	port     string
	password string
	db       int32
	cluster  bool
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
)

//Use a map of bools instead of empty structs so we may disable plugins easily.
var allowedBackends = map[string]bool{
	postgresBackend: true,
	jwtBackend:      true,
	redisBackend:    true,
	httpBackend:     true,
	filesBackend:    true,
	mysqlBackend:    true,
	sqliteBackend:   true,
	mongoBackend:    true,
	pluginBackend:   true,
	grpcBackend:     true,
}

var backends []string          //List of selected backends.
var authOpts map[string]string //Options passed by mosquitto.
var cache Cache                //Cache conf.
var commonData AuthPlugin      //General struct with options and conf.

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int) {

	//Initialize Cache with default values
	cache = Cache{
		host: "localhost",
		port: "6379",
		db:   3,
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	cmBackends := make(map[string]Backend)

	//Initialize common struct with default and given values
	commonData = AuthPlugin{
		aclCacheSeconds:  30,
		authCacheSeconds: 30,
		checkPrefix:      false,
		prefixes:         make(map[string]string),
		logLevel:         log.InfoLevel,
		ctx:              context.Background(),
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
		commonData.disableSuperuser = true
	}

	//Check if log level is given. Set level if any valid option is given.
	if logLevel, ok := authOpts["log_level"]; ok {
		logLevel = strings.Replace(logLevel, " ", "", -1)
		switch logLevel {
		case "debug":
			commonData.logLevel = log.DebugLevel
		case "info":
			commonData.logLevel = log.InfoLevel
		case "warn":
			commonData.logLevel = log.WarnLevel
		case "error":
			commonData.logLevel = log.ErrorLevel
		case "fatal":
			commonData.logLevel = log.FatalLevel
		case "panic":
			commonData.logLevel = log.PanicLevel
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
				commonData.customPlugin = nil
			} else {
				commonData.customPlugin = plug

				plInit, err := commonData.customPlugin.Lookup("Init")

				if err != nil {
					log.Errorf("Couldn't find func Init in plugin: %s", err)
					commonData.customPlugin = nil
					continue
				}

				initFunc := plInit.(func(authOpts map[string]string, logLevel log.Level) error)

				err = initFunc(authOpts, commonData.logLevel)
				if err != nil {
					log.Errorf("Couldn't init plugin: %s", err)
					commonData.customPlugin = nil
					continue
				}

				commonData.PInit = initFunc

				plName, err := commonData.customPlugin.Lookup("GetName")

				if err != nil {
					log.Errorf("Couldn't find func GetName in plugin: %s", err)
					commonData.customPlugin = nil
					continue
				}

				nameFunc := plName.(func() string)
				commonData.customPluginGetName = nameFunc

				plGetUser, err := commonData.customPlugin.Lookup("GetUser")

				if err != nil {
					log.Errorf("couldn't find func GetUser in plugin: %s", err)
					commonData.customPlugin = nil
					continue
				}

				getUserFunc := plGetUser.(func(username, password string) bool)
				commonData.customPluginGetUser = getUserFunc

				plGetSuperuser, err := commonData.customPlugin.Lookup("GetSuperuser")

				if err != nil {
					log.Errorf("couldn't find func GetSuperuser in plugin: %s", err)
					commonData.customPlugin = nil
					continue
				}

				getSuperuserFunc := plGetSuperuser.(func(username string) bool)
				commonData.customPluginGetSuperuser = getSuperuserFunc

				plCheckAcl, err := commonData.customPlugin.Lookup("CheckAcl")

				if err != nil {
					log.Errorf("couldn't find func CheckAcl in plugin: %s", err)
					commonData.customPlugin = nil
					continue
				}

				checkAclFunc := plCheckAcl.(func(username, topic, clientid string, acc int) bool)
				commonData.customPluginCheckAcl = checkAclFunc

				plHalt, err := commonData.customPlugin.Lookup("Halt")

				if err != nil {
					log.Errorf("Couldn't find func Halt in plugin: %s", err)
					commonData.customPlugin = nil
					continue
				}

				haltFunc := plHalt.(func())
				commonData.customPluginHalt = haltFunc

				log.Infof("Backend registered: %s", commonData.customPluginGetName())

			}
		} else {
			switch bename {
			case postgresBackend:
				beIface, err = bes.NewPostgres(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("backend registered: %s", beIface.GetName())
					cmBackends[postgresBackend] = beIface.(bes.Postgres)
				}
			case jwtBackend:
				beIface, err = bes.NewJWT(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[jwtBackend] = beIface.(bes.JWT)
				}
			case filesBackend:
				beIface, err = bes.NewFiles(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[filesBackend] = beIface.(bes.Files)
				}
			case redisBackend:
				beIface, err = bes.NewRedis(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[redisBackend] = beIface.(bes.Redis)
				}
			case mysqlBackend:
				beIface, err = bes.NewMysql(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[mysqlBackend] = beIface.(bes.Mysql)
				}
			case httpBackend:
				beIface, err = bes.NewHTTP(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[httpBackend] = beIface.(bes.HTTP)
				}
			case sqliteBackend:
				beIface, err = bes.NewSqlite(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[sqliteBackend] = beIface.(bes.Sqlite)
				}
			case mongoBackend:
				beIface, err = bes.NewMongo(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[mongoBackend] = beIface.(bes.Mongo)
				}
			case grpcBackend:
				beIface, err = bes.NewGRPC(authOpts, commonData.logLevel)
				if err != nil {
					log.Fatalf("Backend register error: couldn't initialize %s backend with error %s.", bename, err)
				} else {
					log.Infof("Backend registered: %s", beIface.GetName())
					cmBackends[grpcBackend] = beIface.(bes.GRPC)
				}
			}
		}
	}

	if cache, ok := authOpts["cache"]; ok && strings.Replace(cache, " ", "", -1) == "true" {
		log.Info("Cache activated")
		commonData.useCache = true
	} else {
		log.Info("No cache set.")
		commonData.useCache = false
	}

	if commonData.useCache {
		setCache(authOpts)
	}

	if checkPrefix, ok := authOpts["check_prefix"]; ok && strings.Replace(checkPrefix, " ", "", -1) == "true" {
		//Check that backends match prefixes.
		if prefixesStr, ok := authOpts["prefixes"]; ok {
			prefixes := strings.Split(strings.Replace(prefixesStr, " ", "", -1), ",")
			if len(prefixes) == len(backends) {
				//Set prefixes
				for i, backend := range backends {
					commonData.prefixes[prefixes[i]] = backend
				}
				log.Infof("prefixes enabled for backends %s with prefixes %s.", authOpts["backends"], authOpts["prefixes"])
				commonData.checkPrefix = true
			} else {
				log.Errorf("Error: got %d backends and %d prefixes, defaulting to prefixes disabled.", len(backends), len(prefixes))
				commonData.checkPrefix = false
			}

		} else {
			log.Warn("Error: prefixes enabled but no options given, defaulting to prefixes disabled.")
			commonData.checkPrefix = false
		}
	} else {
		commonData.checkPrefix = false
	}
	commonData.backends = cmBackends
}

func setCache(authOpts map[string]string) {
	if cacheHost, ok := authOpts["cache_host"]; ok {
		cache.host = cacheHost
	}

	if cachePort, ok := authOpts["cache_port"]; ok {
		cache.port = cachePort
	}

	if cachePassword, ok := authOpts["cache_password"]; ok {
		cache.password = cachePassword
	}

	if authOpts["cache_mode"] == "true" {
		cache.cluster = true
	}

	if cacheDB, ok := authOpts["cache_db"]; ok {
		db, err := strconv.ParseInt(cacheDB, 10, 32)
		if err == nil {
			cache.db = int32(db)
		} else {
			log.Warningf("couldn't parse cache db (err: %s), defaulting to %d", err, cache.db)
		}
	}

	if authCacheSec, ok := authOpts["auth_cache_seconds"]; ok {
		authSec, err := strconv.ParseInt(authCacheSec, 10, 64)
		if err == nil {
			commonData.authCacheSeconds = authSec
		} else {
			log.Warningf("couldn't parse authCacheSeconds (err: %s), defaulting to %d", err, commonData.authCacheSeconds)
		}
	}

	if aclCacheSec, ok := authOpts["acl_cache_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclCacheSec, 10, 64)
		if err == nil {
			commonData.aclCacheSeconds = aclSec
		} else {
			log.Warningf("couldn't parse aclCacheSeconds (err: %s), defaulting to %d", err, commonData.aclCacheSeconds)
		}
	}

	if cache.cluster {
		addressesOpt := authOpts["redis_cluster_addresses"]
		if addressesOpt == "" {
			log.Errorln("cache Redis cluster addresses missing, defaulting to no cache.")
			commonData.useCache = false
			return
		}

		// Take the given addresses and trim spaces from them.
		addresses := strings.Split(addressesOpt, ",")
		for i := 0; i < len(addresses); i++ {
			addresses[i] = strings.TrimSpace(addresses[i])
		}

		clusterClient := goredis.NewClusterClient(
			&goredis.ClusterOptions{
				Addrs:    addresses,
				Password: cache.password,
			})

		commonData.redisCache = clusterClient
	} else {
		addr := fmt.Sprintf("%s:%s", cache.host, cache.port)
		//If cache is on, try to start redis.
		redisClient := goredis.NewClient(&goredis.Options{
			Addr:     addr,
			Password: cache.password, // no password set
			DB:       int(cache.db),  // use default db
		})

		commonData.redisCache = bes.SingleRedisClient{redisClient}
	}

	_, err := commonData.redisCache.Ping(commonData.ctx).Result()
	if err != nil {
		log.Errorf("couldn't start Redis, defaulting to no cache. error: %s", err)
		commonData.useCache = false
	} else {
		log.Infoln("started cache redis client")
		//Check if cache must be reset
		if cacheReset, ok := authOpts["cache_reset"]; ok && cacheReset == "true" {
			commonData.redisCache.FlushDB(commonData.ctx)
			log.Infoln("flushed cache")
		}
	}
}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password, clientid string) bool {
	var authenticated bool
	var cached bool
	var granted bool
	if commonData.useCache {
		log.Debugf("checking auth cache for %s", username)
		cached, granted = CheckAuthCache(username, password)
		if cached {
			log.Debugf("found in cache: %s", username)
			return granted
		}
	}

	//If prefixes are enabled, check if username has a valid prefix and use the correct backend if so.
	if commonData.checkPrefix {
		validPrefix, bename := CheckPrefix(username)
		if validPrefix {
			if bename == pluginBackend {
				authenticated = CheckPluginAuth(username, password, clientid)
			} else {
				// If the backend is JWT and the token was prefixed, then strip the token. If the token was passed without a prefix it will be handled in the common case.
				if bename == jwtBackend {
					prefix := getPrefixForBackend(bename)
					username = strings.TrimPrefix(username, prefix+"_")
				}
				var backend = commonData.backends[bename]

				if backend.GetUser(username, password, clientid) {
					authenticated = true
					log.Debugf("user %s authenticated with backend %s", username, backend.GetName())
				}
			}
		} else {
			//If there's no valid prefix, check all backends.
			authenticated = CheckBackendsAuth(username, password, clientid)
			//If not authenticated, check for a present plugin
			if !authenticated {
				authenticated = CheckPluginAuth(username, password, clientid)
			}
		}
	} else {
		authenticated = CheckBackendsAuth(username, password, clientid)
		//If not authenticated, check for a present plugin
		if !authenticated {
			authenticated = CheckPluginAuth(username, password, clientid)
		}
	}

	if commonData.useCache {
		authGranted := "false"
		if authenticated {
			authGranted = "true"
		}
		log.Debugf("setting auth cache for %s", username)
		if err := SetAuthCache(username, password, authGranted); err != nil {
			log.Errorf("set auth cache: %s", err)
			return false
		}
	}
	return authenticated
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) bool {
	var aclCheck bool
	var cached bool
	var granted bool
	if commonData.useCache {
		log.Debugf("checking acl cache for %s", username)
		cached, granted = CheckAclCache(username, topic, clientid, acc)
		if cached {
			log.Debugf("found in cache: %s", username)
			return granted
		}
	}
	//If prefixes are enabled, check if username has a valid prefix and use the correct backend if so.
	//Else, check all backends.
	if commonData.checkPrefix {
		validPrefix, bename := CheckPrefix(username)
		if validPrefix {
			if bename == pluginBackend {
				aclCheck = CheckPluginAcl(username, topic, clientid, acc)
			} else {
				// If the backend is JWT and the token was prefixed, then strip the token. If the token was passed without a prefix then it be handled in the common case.
				if bename == jwtBackend {
					prefix := getPrefixForBackend(bename)
					username = strings.TrimPrefix(username, prefix+"_")
				}
				var backend = commonData.backends[bename]
				log.Debugf("Superuser check with backend %s", backend.GetName())
				// Short circuit checks when superusers are disabled.
				if !commonData.disableSuperuser && backend.GetSuperuser(username) {
					log.Debugf("superuser %s acl authenticated with backend %s", username, backend.GetName())
					aclCheck = true
				}
				//If not superuser, check acl.
				if !aclCheck {
					log.Debugf("Acl check with backend %s", backend.GetName())
					if backend.CheckAcl(username, topic, clientid, int32(acc)) {
						log.Debugf("user %s acl authenticated with backend %s", username, backend.GetName())
						aclCheck = true
					}
				}
			}
		} else {
			//If there's no valid prefix, check all backends.
			aclCheck = CheckBackendsAcl(username, topic, clientid, acc)
			//If acl hasn't passed, check for plugin.
			if !aclCheck {
				aclCheck = CheckPluginAcl(username, topic, clientid, acc)
			}
		}
	} else {
		aclCheck = CheckBackendsAcl(username, topic, clientid, acc)
		//If acl hasn't passed, check for plugin.
		if !aclCheck {
			aclCheck = CheckPluginAcl(username, topic, clientid, acc)
		}
	}

	if commonData.useCache {
		authGranted := "false"
		if aclCheck {
			authGranted = "true"
		}
		log.Debugf("setting acl cache (granted = %s) for %s", authGranted, username)
		if err := SetAclCache(username, topic, clientid, acc, authGranted); err != nil {
			log.Errorf("set acl cache: %s", err)
			return false
		}
	}

	log.Debugf("Acl is %t for user %s", aclCheck, username)
	return aclCheck
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//CheckAuthCache checks if the username/password pair is present in the cache. Return if it's present and, if so, if it was granted privileges.
func CheckAuthCache(username, password string) (bool, bool) {
	record := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("auth%s%s", username, password)))

	present, granted, err := checkCacheRecord(record, commonData.authCacheSeconds)
	if err == nil {
		return present, granted
	}

	if bes.IsMovedError(err) {
		err = commonData.redisCache.ReloadState(commonData.ctx)
		// This should not happen, ever!
		if err == bes.SingleClientError {
			return false, false
		}

		//Retry once.
		present, granted, err = checkCacheRecord(record, commonData.authCacheSeconds)
	}

	if err != nil {
		log.Debugf("set cache error: %s", err)
	}

	return present, granted
}

//CheckAclCache checks if the username/topic/clientid/acc mix is present in the cache. Return if it's present and, if so, if it was granted privileges.
func CheckAclCache(username, topic, clientid string, acc int) (bool, bool) {
	record := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("acl%s%s%s%d", username, topic, clientid, acc)))

	present, granted, err := checkCacheRecord(record, commonData.aclCacheSeconds)
	if err == nil {
		return present, granted
	}

	if bes.IsMovedError(err) {
		err = commonData.redisCache.ReloadState(commonData.ctx)
		// This should not happen, ever!
		if err == bes.SingleClientError {
			return false, false
		}

		//Retry once.
		present, granted, err = checkCacheRecord(record, commonData.aclCacheSeconds)
	}

	if err != nil {
		log.Debugf("set cache error: %s", err)
	}

	return present, granted
}

func checkCacheRecord(record string, expirationTime int64) (bool, bool, error) {
	val, err := commonData.redisCache.Get(commonData.ctx, record).Result()
	if err != nil {
		return false, false, err
	}

	//refresh expiration
	_, err = commonData.redisCache.Expire(commonData.ctx, record, time.Duration(expirationTime)*time.Second).Result()
	if err != nil {
		return false, false, err
	}

	if val == "true" {
		return true, true, nil
	}

	return true, false, nil
}

//SetAuthCache sets a pair, granted option and expiration time.
func SetAuthCache(username, password string, granted string) error {
	record := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("auth%s%s", username, password)))
	err := setCacheRecord(record, granted, commonData.authCacheSeconds)

	if err == nil {
		return nil
	}

	// If record was moved, reload and retry.
	if bes.IsMovedError(err) {
		err = commonData.redisCache.ReloadState(commonData.ctx)
		if err != nil {
			return err
		}

		//Retry once.
		err = setCacheRecord(record, granted, commonData.authCacheSeconds)
	}

	return err
}

//SetAclCache sets a mix, granted option and expiration time.
func SetAclCache(username, topic, clientid string, acc int, granted string) error {
	record := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("acl%s%s%s%d", username, topic, clientid, acc)))
	err := setCacheRecord(record, granted, commonData.aclCacheSeconds)

	if err == nil {
		return nil
	}

	// If record was moved, reload and retry.
	if bes.IsMovedError(err) {
		err = commonData.redisCache.ReloadState(commonData.ctx)
		if err != nil {
			return err
		}

		//Retry once.
		err = setCacheRecord(record, granted, commonData.aclCacheSeconds)
	}

	return err
}

func setCacheRecord(record string, granted string, expirationTime int64) error {
	return commonData.redisCache.Set(commonData.ctx, record, granted, time.Duration(expirationTime)*time.Second).Err()
}

//checkPrefix checks if a username contains a valid prefix. If so, returns ok and the suitable backend name; else, !ok and empty string.
func CheckPrefix(username string) (bool, string) {
	if strings.Index(username, "_") > 0 {
		userPrefix := username[0:strings.Index(username, "_")]
		if prefix, ok := commonData.prefixes[userPrefix]; ok {
			log.Debugf("Found prefix for user %s, using backend %s.", username, prefix)
			return true, prefix
		}
	}
	return false, ""
}

//getPrefixForBackend retrieves the user provided prefix for a given backend.
func getPrefixForBackend(backend string) string {
	for k, v := range commonData.prefixes {
		if v == backend {
			return k
		}
	}
	return ""
}

//CheckBackendsAuth checks for all backends if a username is authenticated and sets the authenticated param.
func CheckBackendsAuth(username, password, clientid string) bool {

	authenticated := false

	for _, bename := range backends {

		if bename == pluginBackend {
			continue
		}

		var backend = commonData.backends[bename]

		log.Debugf("checking user %s with backend %s", username, backend.GetName())

		if backend.GetUser(username, password, clientid) {
			authenticated = true
			log.Debugf("user %s authenticated with backend %s", username, backend.GetName())
			break
		}
	}

	return authenticated

}

//CheckBackendsAcl  checks for all backends if a username is superuser or has acl rights and sets the aclCheck param.
func CheckBackendsAcl(username, topic, clientid string, acc int) bool {
	//Check superusers first
	aclCheck := false
	if !commonData.disableSuperuser {
		for _, bename := range backends {
			if bename == pluginBackend {
				continue
			}
			var backend = commonData.backends[bename]
			log.Debugf("Superuser check with backend %s", backend.GetName())
			if backend.GetSuperuser(username) {
				log.Debugf("superuser %s acl authenticated with backend %s", username, backend.GetName())
				aclCheck = true
				break
			}
		}
	}

	if !aclCheck {
		for _, bename := range backends {
			if bename == pluginBackend {
				continue
			}
			var backend = commonData.backends[bename]
			log.Debugf("Acl check with backend %s", backend.GetName())
			if backend.CheckAcl(username, topic, clientid, int32(acc)) {
				log.Debugf("user %s acl authenticated with backend %s", username, backend.GetName())
				aclCheck = true
				break
			}
		}
	}

	return aclCheck
}

//CheckPluginAuth checks that the plugin is not nil and returns the plugins auth response.
func CheckPluginAuth(username, password, clientid string) bool {
	if commonData.customPlugin == nil {
		return false
	}
	return commonData.customPluginGetUser(username, password)
}

//CheckPluginAcl checks that the plugin is not nil and returns the superuser/acl response.
func CheckPluginAcl(username, topic, clientid string, acc int) bool {
	if commonData.customPlugin == nil {
		return false
	}
	//If superuser, authorize it unless superusers are disabled.
	if !commonData.disableSuperuser && commonData.customPluginGetSuperuser(username) {
		return true
	}
	//Check against the plugin's check acl function.
	return commonData.customPluginCheckAcl(username, topic, clientid, acc)
}

//export AuthPluginCleanup
func AuthPluginCleanup() {
	log.Info("Cleaning up plugin")
	//If cache is set, close cache connection.
	if commonData.redisCache != nil {
		commonData.redisCache.Close()
	}

	//Halt every registered backend.
	for _, v := range commonData.backends {
		v.Halt()
	}

	if commonData.customPlugin != nil {
		commonData.customPluginHalt()
	}
}

func main() {}
