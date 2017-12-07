package backends

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/iegomez/mosquitto-go-auth-plugin/common"

	goredis "github.com/go-redis/redis"
)

type Redis struct {
	Host     string
	Port     string
	Password string
	DB       int32
	Conn     *goredis.Client
}

func NewRedis(authOpts map[string]string) (Redis, error) {

	var redis = Redis{
		Host:     "localhost",
		Port:     "6379",
		Password: "",
		DB:       1,
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
		log.Printf("Found redis db %s\n", authOpts["redis_db"])
		db, err := strconv.ParseInt(redisDB, 10, 32)
		if err != nil {
			redis.DB = int32(db)
		}
		log.Printf("Setting redis DB: %d\n", db)
	}

	addr := fmt.Sprintf("%s:%s", redis.Host, redis.Port)

	log.Printf("starting redis client with db %d\n", redis.DB)

	//Try to start redis.
	goredisClient := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: redis.Password, // no password set
		DB:       int(redis.DB),  // use default DB
	})

	_, err := goredisClient.Ping().Result()
	if err != nil {
		log.Fatalf("couldn't start redis backend. error: %s\n", err)
	}

	redis.Conn = goredisClient

	return redis, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Redis) GetUser(username, password string) bool {

	log.Printf("Checking redis user with user %s and pass %s for conn %v.\n", username, password, o.Conn)

	pwHash, err := o.Conn.Get(username).Result()

	if err != nil {
		log.Printf("Redis get user error: %s\n", err)
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
		log.Printf("Redis get superuser error: %s\n", err)
		return false
	}

	if isSuper == "true" {
		return true
	}

	return false

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Redis) CheckAcl(username, topic, clientid string, acc int32) bool {

	var acls []string
	var err error

	acls, err = o.Conn.SMembers(fmt.Sprintf("%s:acls", username)).Result()

	if err != nil {
		log.Printf("Redis check acl error: %s\n", err)
		return false
	}

	for _, acl := range acls {
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
