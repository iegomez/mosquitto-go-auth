package backends

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
)

func TestBackends(t *testing.T) {
	/*
		No way we're gonna test every possibility given the amount of backends,
		let's just make a sanity check for relevant functionality:

		- Test there must be at least one user and acl checker.
		- Test backend is valid.
		- Test non registered checks are skipped.
		- Test checking user and acls from different backends works.
		- Test initialization actually returns a useful initialized struct.

	*/

	authOpts := make(map[string]string)

	pwPath, _ := filepath.Abs("../test-files/passwords")
	aclPath, _ := filepath.Abs("../test-files/acls")

	authOpts["password_path"] = pwPath
	authOpts["acl_path"] = aclPath

	authOpts["redis_host"] = "localhost"
	authOpts["redis_port"] = "6379"
	authOpts["redis_db"] = "2"
	authOpts["redis_password"] = ""

	backends := []string{"files", "redis"}

	username := "test1"
	password := "test1"
	passwordHash := "PBKDF2$sha512$100000$2WQHK5rjNN+oOT+TZAsWAw==$TDf4Y6J+9BdnjucFQ0ZUWlTwzncTjOOeE00W4Qm8lfPQyPCZACCjgfdK353jdGFwJjAf6vPAYaba9+z4GWK7Gg=="
	clientid := "clientid"

	Convey("An unknown backend should result in an error", t, func() {
		backends := []string{"unknown"}

		authOpts["backends"] = "unkown"

		_, err := Initialize(authOpts, log.DebugLevel, backends)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "unkown backend unknown")
	})

	Convey("On initialization, lacking user/acl checkers should result in an error", t, func() {
		authOpts["backends"] = "files, redis"
		authOpts["files_register"] = "user"
		authOpts["redis_register"] = "user"

		_, err := Initialize(authOpts, log.DebugLevel, backends)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "no backend registered ACL checks")

		authOpts["backends"] = "files, redis"
		authOpts["files_register"] = "acl"
		authOpts["redis_register"] = "acl"

		_, err = Initialize(authOpts, log.DebugLevel, backends)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "no backend registered user checks")
	})

	Convey("On initialization, unknown checkers should result in an error", t, func() {
		authOpts["backends"] = "files, redis"
		authOpts["files_register"] = "user"
		authOpts["redis_register"] = "unknown"

		_, err := Initialize(authOpts, log.DebugLevel, backends)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "unsupported check unknown found for backend redis")
	})

	Convey("We should be able to auth users with one backend and acls with a different one", t, func() {
		authOpts["backends"] = "files, redis"
		authOpts["files_register"] = "acl"
		authOpts["redis_register"] = "user"

		redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
		assert.Nil(t, err)

		ctx := context.Background()

		// Insert a user to test auth
		username = "test1"
		redis.conn.Set(ctx, username, passwordHash, 0)

		b, err := Initialize(authOpts, log.DebugLevel, backends)
		So(err, ShouldBeNil)

		// Redis only contains test1, while files has a bunch of more users.
		// Since Files only registers acl checks, those users should fail.
		tt1, err1 := b.checkAuth(username, password, clientid)
		tt2, err2 := b.checkAuth("test2", "test2", clientid)

		So(err1, ShouldBeNil)
		So(tt1, ShouldBeTrue)
		So(err2, ShouldBeNil)
		So(tt2, ShouldBeFalse)

		/*
			Files grants these to user test1:

			user test1
			topic write test/topic/1
			topic read test/topic/2
			topic readwrite readwrite/topic

			So if we add test/redis topic to Redis, the user should not have permission because acl chekcs are done by Files only.

		*/

		redis.conn.SAdd(ctx, username+":racls", "test/redis")

		aclCheck, err := b.checkAcl(username, "test/redis", clientid, 1)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeFalse)

		aclCheck, err = b.checkAcl(username, "test/topic/1", clientid, 2)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeTrue)
	})

	Convey("When not registering checks, all of them should be available", t, func() {
		authOpts["backends"] = "files, redis"
		delete(authOpts, "files_register")
		delete(authOpts, "redis_register")

		redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
		assert.Nil(t, err)

		ctx := context.Background()

		// Insert a user to test auth
		username = "test1"
		redis.conn.Set(ctx, username, passwordHash, 0)

		b, err := Initialize(authOpts, log.DebugLevel, backends)
		So(err, ShouldBeNil)

		tt1, err1 := b.checkAuth(username, password, clientid)
		tt2, err2 := b.checkAuth("test2", "test2", clientid)

		So(err1, ShouldBeNil)
		So(tt1, ShouldBeTrue)
		So(err2, ShouldBeNil)
		So(tt2, ShouldBeTrue)

		/*
			Files grants these to user test1:

			user test1
			topic write test/topic/1
			topic read test/topic/2
			topic readwrite readwrite/topic

			Now the user should have permission for the redis topic since all backends do acl checks.

		*/

		redis.conn.SAdd(ctx, username+":racls", "test/redis")

		aclCheck, err := b.checkAcl(username, "test/redis", clientid, 1)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeTrue)

		aclCheck, err = b.checkAcl(username, "test/topic/1", clientid, 2)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeTrue)
	})
}
