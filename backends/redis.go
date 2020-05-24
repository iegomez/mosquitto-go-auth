package backends

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	goredis "github.com/go-redis/redis/v8"
	"github.com/iegomez/mosquitto-go-auth/common"
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
}

func NewRedis(authOpts map[string]string, logLevel log.Level) (Redis, error) {

	log.SetLevel(logLevel)

	var redis = Redis{
		Host:         "localhost",
		Port:         "6379",
		DB:           1,
		SaltEncoding: "base64",
		ctx:          context.Background(),
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

	if saltEncoding, ok := authOpts["redis_salt_encoding"]; ok {
		switch saltEncoding {
		case common.Base64, common.UTF8:
			redis.SaltEncoding = saltEncoding
			log.Debugf("redis backend: set salt encoding to: %s", saltEncoding)
		default:
			log.Errorf("redis backend: invalid salt encoding specified: %s, will default to base64 instead", saltEncoding)
		}
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
		redis.conn = redisClient
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

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Redis) GetUser(username, password, clientid string) bool {

	pwHash, err := o.conn.Get(o.ctx, username).Result()

	if err != nil {
		log.Debugf("Redis get user error: %s", err)
		return false
	}

	if common.HashCompare(password, pwHash, o.SaltEncoding) {
		return true
	}

	return false

}

//GetSuperuser checks that the key username:su exists and has value "true".
func (o Redis) GetSuperuser(username string) bool {

	if o.disableSuperuser {
		return false
	}

	isSuper, err := o.conn.Get(o.ctx, fmt.Sprintf("%s:su", username)).Result()

	if err != nil {
		log.Debugf("Redis get superuser error: %s", err)
		return false
	}

	if isSuper == "true" {
		return true
	}

	return false

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Redis) CheckAcl(username, topic, clientid string, acc int32) bool {

	var acls []string       //User specific acls.
	var commonAcls []string //Common acls.

	//We need to check if client is subscribing, reading or publishing to get correct acls.
	switch acc {
	case MOSQ_ACL_SUBSCRIBE:
		//Get all user subscribe acls.
		var err error
		acls, err = o.conn.SMembers(o.ctx, fmt.Sprintf("%s:sacls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}

		//Get common subscribe acls.
		commonAcls, err = o.conn.SMembers(o.ctx, "common:sacls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}

	case MOSQ_ACL_READ:
		//Get all user read and readwrite acls.
		urAcls, err := o.conn.SMembers(o.ctx, fmt.Sprintf("%s:racls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}
		urwAcls, err := o.conn.SMembers(o.ctx, fmt.Sprintf("%s:rwacls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}

		//Get common read and readwrite acls
		rAcls, err := o.conn.SMembers(o.ctx, "common:racls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}
		rwAcls, err := o.conn.SMembers(o.ctx, "common:rwacls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
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
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}
		urwAcls, err := o.conn.SMembers(o.ctx, fmt.Sprintf("%s:rwacls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}

		//Get common write and readwrite acls
		wAcls, err := o.conn.SMembers(o.ctx, "common:wacls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
		}
		rwAcls, err := o.conn.SMembers(o.ctx, "common:rwacls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s", err)
			return false
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
		if common.TopicsMatch(acl, topic) {
			return true
		}
	}

	for _, acl := range commonAcls {
		aclTopic := strings.Replace(acl, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)
		if common.TopicsMatch(aclTopic, topic) {
			return true
		}
	}

	return false

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
