package backends

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	goredis "github.com/go-redis/redis/v8"
	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
)

type RedisClient interface {
	Get(ctx context.Context, key string) *goredis.StringCmd
	SMembers(ctx context.Context, key string) *goredis.StringSliceCmd
	Ping(ctx context.Context) *goredis.StatusCmd
	Close() error
	FlushDB(ctx context.Context) *goredis.StatusCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *goredis.StatusCmd
	SAdd(ctx context.Context, key string, members ...interface{}) *goredis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *goredis.BoolCmd
	ReloadState(ctx context.Context)
}

type SingleRedisClient struct {
	*goredis.Client
}

func (c SingleRedisClient) ReloadState(ctx context.Context) {
	// NO-OP
}

type Redis struct {
	Host             string
	Port             string
	Password         string
	SaltEncoding     string
	DB               int32
	conn             RedisClient
	disableSuperuser bool
	ctx              context.Context
	hasher           hashing.HashComparer
}

func NewRedis(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (Redis, error) {

	log.SetLevel(logLevel)

	var redis = Redis{
		Host:         "localhost",
		Port:         "6379",
		DB:           1,
		SaltEncoding: "base64",
		ctx:          context.Background(),
		hasher:       hasher,
	}

	if authOpts["redis_disable_superuser"] == "true" {
		redis.disableSuperuser = true
	}

	if redisHost, ok := authOpts["redis_host"]; ok {
		redis.Host = redisHost
	}

	if redisPort, ok := authOpts["redis_port"]; ok {
		redis.Port = redisPort
	}

	if redisPassword, ok := authOpts["redis_password"]; ok {
		redis.Password = redisPassword
	}

	if redisDB, ok := authOpts["redis_db"]; ok {
		db, err := strconv.ParseInt(redisDB, 10, 32)
		if err == nil {
			redis.DB = int32(db)
		}
	}

	if authOpts["redis_mode"] == "cluster" {

		addressesOpt := authOpts["redis_cluster_addresses"]
		if addressesOpt == "" {
			return redis, fmt.Errorf("redis backend: missing Redis Cluster addresses")
		}

		// Take the given addresses and trim spaces from them.
		addresses := strings.Split(addressesOpt, ",")
		for i := 0; i < len(addresses); i++ {
			addresses[i] = strings.TrimSpace(addresses[i])
		}

		clusterClient := goredis.NewClusterClient(
			&goredis.ClusterOptions{
				Addrs:    addresses,
				Password: redis.Password,
			})
		redis.conn = clusterClient
	} else {
		addr := fmt.Sprintf("%s:%s", redis.Host, redis.Port)

		redisClient := goredis.NewClient(&goredis.Options{
			Addr:     addr,
			Password: redis.Password,
			DB:       int(redis.DB),
		})
		redis.conn = &SingleRedisClient{redisClient}
	}

	for {
		if _, err := redis.conn.Ping(redis.ctx).Result(); err != nil {
			log.Errorf("ping redis error, will retry in 2s: %s", err)
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}

	return redis, nil

}

// Checks if an error was caused by a moved record in a cluster.
func isMovedError(err error) bool {
	s := err.Error()
	if strings.HasPrefix(s, "MOVED ") || strings.HasPrefix(s, "ASK ") {
		return true
	}

	return false
}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Redis) GetUser(username, password, _ string) (bool, error) {
	ok, err := o.getUser(username, password)
	if err == nil {
		return ok, nil
	}

	//If using Redis Cluster, reload state and attempt once more.
	if isMovedError(err) {
		o.conn.ReloadState(o.ctx)

		//Retry once.
		ok, err = o.getUser(username, password)
	}

	if err != nil {
		log.Debugf("redis get user error: %s", err)
	}
	return ok, err
}

func (o Redis) getUser(username, password string) (bool, error) {
	pwHash, err := o.conn.Get(o.ctx, username).Result()
	if err == goredis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}

	if o.hasher.Compare(password, pwHash) {
		return true, nil
	}

	return false, nil
}

//GetSuperuser checks that the key username:su exists and has value "true".
func (o Redis) GetSuperuser(username string) (bool, error) {
	if o.disableSuperuser {
		return false, nil
	}

	ok, err := o.getSuperuser(username)
	if err == nil {
		return ok, nil
	}

	//If using Redis Cluster, reload state and attempt once more.
	if isMovedError(err) {
		o.conn.ReloadState(o.ctx)

		//Retry once.
		ok, err = o.getSuperuser(username)
	}

	if err != nil {
		log.Debugf("redis get superuser error: %s", err)
	}

	return ok, err
}

func (o Redis) getSuperuser(username string) (bool, error) {
	isSuper, err := o.conn.Get(o.ctx, fmt.Sprintf("%s:su", username)).Result()
	if err == goredis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}

	if isSuper == "true" {
		return true, nil
	}

	return false, nil
}

func (o Redis) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	ok, err := o.checkAcl(username, topic, clientid, acc)
	if err == nil {
		return ok, nil
	}

	//If using Redis Cluster, reload state and attempt once more.
	if isMovedError(err) {
		o.conn.ReloadState(o.ctx)

		//Retry once.
		ok, err = o.checkAcl(username, topic, clientid, acc)
	}

	if err != nil {
		log.Debugf("redis check acl error: %s", err)
	}
	return ok, err
}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Redis) checkAcl(username, topic, clientid string, acc int32) (bool, error) {

	var acls []string       //User specific acls.
	var commonAcls []string //Common acls.

	//We need to check if client is subscribing, reading or publishing to get correct acls.
	switch acc {
	case MOSQ_ACL_SUBSCRIBE:
		//Get all user subscribe acls.
		var err error
		acls, err = o.conn.SMembers(o.ctx, fmt.Sprintf("%s:sacls", username)).Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}

		//Get common subscribe acls.
		commonAcls, err = o.conn.SMembers(o.ctx, "common:sacls").Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}

	case MOSQ_ACL_READ:
		//Get all user read and readwrite acls.
		urAcls, err := o.conn.SMembers(o.ctx, fmt.Sprintf("%s:racls", username)).Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}
		urwAcls, err := o.conn.SMembers(o.ctx, fmt.Sprintf("%s:rwacls", username)).Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}

		//Get common read and readwrite acls
		rAcls, err := o.conn.SMembers(o.ctx, "common:racls").Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}
		rwAcls, err := o.conn.SMembers(o.ctx, "common:rwacls").Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}

		acls = make([]string, len(urAcls)+len(urwAcls))
		acls = append(acls, urAcls...)
		acls = append(acls, urwAcls...)

		commonAcls = make([]string, len(rAcls)+len(rwAcls))
		commonAcls = append(commonAcls, rAcls...)
		commonAcls = append(commonAcls, rwAcls...)
	case MOSQ_ACL_WRITE:
		//Get all user write and readwrite acls.
		uwAcls, err := o.conn.SMembers(o.ctx, fmt.Sprintf("%s:wacls", username)).Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}
		urwAcls, err := o.conn.SMembers(o.ctx, fmt.Sprintf("%s:rwacls", username)).Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}

		//Get common write and readwrite acls
		wAcls, err := o.conn.SMembers(o.ctx, "common:wacls").Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}
		rwAcls, err := o.conn.SMembers(o.ctx, "common:rwacls").Result()
		if err == goredis.Nil {
			return false, nil
		} else if err != nil {
			return false, err
		}

		acls = make([]string, len(uwAcls)+len(urwAcls))
		acls = append(acls, uwAcls...)
		acls = append(acls, urwAcls...)

		commonAcls = make([]string, len(wAcls)+len(rwAcls))
		commonAcls = append(commonAcls, wAcls...)
		commonAcls = append(commonAcls, rwAcls...)
	}

	//Now loop through acls looking for a match.
	for _, acl := range acls {
		if topics.Match(acl, topic) {
			return true, nil
		}
	}

	for _, acl := range commonAcls {
		aclTopic := strings.Replace(acl, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)
		if topics.Match(aclTopic, topic) {
			return true, nil
		}
	}

	return false, nil
}

//GetName returns the backend's name
func (o Redis) GetName() string {
	return "Redis"
}

//Halt terminates the connection.
func (o Redis) Halt() {
	if o.conn != nil {
		err := o.conn.Close()
		if err != nil {
			log.Errorf("Redis cleanup error: %s", err)
		}
	}
}
