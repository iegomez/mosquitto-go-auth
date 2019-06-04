package backends

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/iegomez/mosquitto-go-auth/common"

	goredis "github.com/go-redis/redis"
)

type Redis struct {
	Host     string
	Port     string
	Password string
	DB       int32
	Conn     *goredis.Client
}

func NewRedis(authOpts map[string]string, logLevel log.Level) (Redis, error) {

	log.SetLevel(logLevel)

	var redis = Redis{
		Host: "localhost",
		Port: "6379",
		DB:   1,
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

	addr := fmt.Sprintf("%s:%s", redis.Host, redis.Port)

	//Try to start redis.
	goredisClient := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: redis.Password,
		DB:       int(redis.DB),
	})

	for {
		if _, err := goredisClient.Ping().Result(); err != nil {
			log.Errorf("ping redis error, will retry in 2s: %s", err)
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}

	redis.Conn = goredisClient

	return redis, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Redis) GetUser(username, password string) bool {

	pwHash, err := o.Conn.Get(username).Result()

	if err != nil {
		log.Debugf("Redis get user error: %s\n", err)
		return false
	}

	if common.HashCompare(password, pwHash) {
		return true
	}

	return false

}

//GetSuperuser checks that the key username:su exists and has value "true".
func (o Redis) GetSuperuser(username string) bool {

	isSuper, err := o.Conn.Get(fmt.Sprintf("%s:su", username)).Result()

	if err != nil {
		log.Debugf("Redis get superuser error: %s\n", err)
		return false
	}

	if isSuper == "true" {
		return true
	}

	return false

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Redis) CheckAcl(username, topic, clientid string, acc int32) bool {

	//We need to check if client is subscribing or publishing to get correct acls.

	if acc == 1 {
		//Subscribe

		//Get all user read and readwrite acls.
		urAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:racls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}
		urwAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:rwacls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}

		//Get common read and readwrite acls
		rAcls, err := o.Conn.SMembers("common:racls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}
		rwAcls, err := o.Conn.SMembers("common:rwacls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}

		acls := make([]string, len(urAcls)+len(urwAcls), len(urAcls)+len(urwAcls))
		acls = append(acls, urAcls...)
		acls = append(acls, urwAcls...)

		commonAcls := make([]string, len(rAcls)+len(rwAcls), len(rAcls)+len(rwAcls))
		commonAcls = append(commonAcls, rAcls...)
		commonAcls = append(commonAcls, rwAcls...)

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

	} else if acc == 2 {
		//Publish

		//Get all user write and readwrite acls.
		uwAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:wacls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}
		urwAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:rwacls", username)).Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}

		//Get common write and readwrite acls
		wAcls, err := o.Conn.SMembers("common:wacls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}
		rwAcls, err := o.Conn.SMembers("common:rwacls").Result()
		if err != nil {
			log.Debugf("Redis check acl error: %s\n", err)
			return false
		}

		acls := make([]string, len(uwAcls)+len(urwAcls), len(uwAcls)+len(urwAcls))
		acls = append(acls, uwAcls...)
		acls = append(acls, urwAcls...)

		commonAcls := make([]string, len(wAcls)+len(rwAcls), len(wAcls)+len(rwAcls))
		commonAcls = append(commonAcls, wAcls...)
		commonAcls = append(commonAcls, rwAcls...)

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

	}

	return false

}

//GetName returns the backend's name
func (o Redis) GetName() string {
	return "Redis"
}

//Halt terminates the connection.
func (o Redis) Halt() {
	if o.Conn != nil {
		err := o.Conn.Close()
		if err != nil {
			log.Errorf("Redis cleanup error: %s", err)
		}
	}
}
