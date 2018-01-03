package backends

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

var rbUsername = "test"
var rbUserPass = "testpw"
var rbUserPassHash = "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$BK1BQ2wbwU1zNxv3Ml3wLuu5//hPop3/LvaPYjjCwdBvnpwusnukJPpcXQzyyjOlZdieXTx6sXAcX4WnZRZZnw=="

var strictAcl = "test/topic/1"
var singleLevelAcl = "test/topic/+"
var hierarchyAcl = "test/#"

var userPattern = "test/%u"
var clientPattern = "test/%c"

var rbClientID = "test_client"

var rbTestTopic1 = `test/topic/1`

var redis Redis

func init() {
	var authOpts = map[string]string{
		"redis_host": "localhost",
		"redis_port": "6379",
		"redis_db":   "2",
	}

	redis, _ = NewRedis(authOpts, log.ErrorLevel)
	redis.Conn.FlushDB()
}

func BenchmarkRedisUser(b *testing.B) {
	redis.Conn.Set(rbUsername, rbUserPassHash, 0)
	for n := 0; n < b.N; n++ {
		redis.GetUser(rbUsername, rbUserPass)
	}
	redis.Conn.FlushDB()
}

func BenchmarkRedisSuperuser(b *testing.B) {
	redis.Conn.Set(rbUsername, rbUserPassHash, 0)
	redis.Conn.Set(rbUsername+":su", "true", 0)
	for n := 0; n < b.N; n++ {
		redis.GetSuperuser(rbUsername)
	}
	redis.Conn.FlushDB()
}

func BenchmarkRedisStrictAcl(b *testing.B) {
	redis.Conn.SAdd(rbUsername+":acls", strictAcl)
	for n := 0; n < b.N; n++ {
		redis.CheckAcl(rbUsername, rbTestTopic1, rbClientID, 1)
	}
	redis.Conn.FlushDB()
}

func BenchmarkRedisUserPatternAcl(b *testing.B) {
	redis.Conn.SAdd(rbUsername+":acls", userPattern)
	for n := 0; n < b.N; n++ {
		redis.CheckAcl(rbUsername, "test/test", rbClientID, 1)
	}
	redis.Conn.FlushDB()
}

func BenchmarkRedisClientPatternAcl(b *testing.B) {
	redis.Conn.SAdd(rbUsername+":acls", clientPattern)
	for n := 0; n < b.N; n++ {
		redis.CheckAcl(rbUsername, "test/test_client", rbClientID, 1)
	}
	redis.Conn.FlushDB()
}

func BenchmarkRedisSingleLevelAcl(b *testing.B) {
	redis.Conn.SAdd(rbUsername+":acls", singleLevelAcl)
	for n := 0; n < b.N; n++ {
		redis.CheckAcl(rbUsername, "test/topic/whatever", rbClientID, 1)
	}
	redis.Conn.FlushDB()
}

func BenchmarkRedisHierarchyAcl(b *testing.B) {
	redis.Conn.SAdd(rbUsername+":acls", hierarchyAcl)
	for n := 0; n < b.N; n++ {
		redis.CheckAcl(rbUsername, "test/what/ever", rbClientID, 1)
	}
	redis.Conn.FlushDB()
}
