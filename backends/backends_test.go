package backends

import (
	"context"
	"fmt"
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

	authOpts["files_password_path"] = pwPath
	authOpts["files_acl_path"] = aclPath

	authOpts["redis_host"] = "localhost"
	authOpts["redis_port"] = "6379"
	authOpts["redis_db"] = "2"
	authOpts["redis_password"] = ""

	username := "test1"
	password := "test1"
	passwordHash := "PBKDF2$sha512$100000$2WQHK5rjNN+oOT+TZAsWAw==$TDf4Y6J+9BdnjucFQ0ZUWlTwzncTjOOeE00W4Qm8lfPQyPCZACCjgfdK353jdGFwJjAf6vPAYaba9+z4GWK7Gg=="
	clientid := "clientid"

	version := "2.0.0"

	Convey("Missing or empty backends option should result in an error", t, func() {
		authOpts["backends"] = ""

		_, err := Initialize(authOpts, log.DebugLevel, version)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "missing or blank option backends")

		delete(authOpts, "backends")

		_, err = Initialize(authOpts, log.DebugLevel, version)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "missing or blank option backends")
	})

	Convey("An unknown backend should result in an error", t, func() {
		authOpts["backends"] = "unknown"

		_, err := Initialize(authOpts, log.DebugLevel, version)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "unknown backend unknown")
	})

	Convey("On initialization, unknown checkers should result in an error", t, func() {
		authOpts["backends"] = "files, redis"
		authOpts["files_register"] = "user"
		authOpts["redis_register"] = "unknown"

		_, err := Initialize(authOpts, log.DebugLevel, version)
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

		b, err := Initialize(authOpts, log.DebugLevel, version)
		So(err, ShouldBeNil)

		// Redis only contains test1, while files has a bunch of more users.
		// Since Files only registers acl checks, those users should fail.
		tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)
		tt2, err2 := b.AuthUnpwdCheck("test2", "test2", clientid)

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

		aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeFalse)

		aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 2)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeTrue)

		redis.Halt()
	})

	Convey("When not registering checks, all of them should be available", t, func() {
		authOpts["backends"] = "files, redis"
		delete(authOpts, "files_register")
		delete(authOpts, "redis_register")

		redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
		assert.Nil(t, err)

		ctx := context.Background()

		// Insert a user to test auth
		redis.conn.Set(ctx, username, passwordHash, 0)

		b, err := Initialize(authOpts, log.DebugLevel, version)
		So(err, ShouldBeNil)

		tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)
		tt2, err2 := b.AuthUnpwdCheck("test2", "test2", clientid)

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

		aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeTrue)

		aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 2)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeTrue)

		redis.Halt()
	})

	Convey("Without prefixes", t, func() {
		Convey("When superusers are enabled but the backend is not registered to check them, it'll skip to acls", func() {
			authOpts["backends"] = "redis"
			authOpts["redis_register"] = "user, acl"
			authOpts["check_prefix"] = "false"
			delete(authOpts, "prefixes")

			username := "redis_test1"
			password := username
			passwordHash := "PBKDF2$sha512$100000$hgodnayqjfs0AOCxvsU+Zw==$dfc4LBGmZ/wB128NOD48qF5fCS+r/bsjU+oCXgT3UksAik73vIkXcPFydtbJKoIgnepNXP9t+zGIaR5wyRmXaA=="

			redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
			assert.Nil(t, err)

			ctx := context.Background()

			// Insert a user to test auth.
			redis.conn.Set(ctx, username, passwordHash, 0)
			// Set it as superuser.
			redis.conn.Set(ctx, fmt.Sprintf("%s:su", username), "true", 0)

			b, err := Initialize(authOpts, log.DebugLevel, version)
			So(err, ShouldBeNil)

			tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)

			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)

			// Set a topic and check. Since the backend doesn't register superuser,
			// it should only be able to access that topic and nothing else even if superuser checks are not generally disabled.
			redis.conn.SAdd(ctx, username+":racls", "test/redis")

			So(b.disableSuperuser, ShouldBeFalse)

			aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeFalse)

			redis.Halt()
		})

		Convey("When superusers are disabled, even if the backend registers checks, it'll skip to acls", func() {
			authOpts["backends"] = "redis"
			authOpts["redis_register"] = "user, superuser, acl"
			authOpts["disable_superuser"] = "true"
			authOpts["check_prefix"] = "false"
			delete(authOpts, "prefixes")

			username := "redis_test1"
			password := username
			passwordHash := "PBKDF2$sha512$100000$hgodnayqjfs0AOCxvsU+Zw==$dfc4LBGmZ/wB128NOD48qF5fCS+r/bsjU+oCXgT3UksAik73vIkXcPFydtbJKoIgnepNXP9t+zGIaR5wyRmXaA=="

			redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
			assert.Nil(t, err)

			ctx := context.Background()

			// Insert a user to test auth.
			redis.conn.Set(ctx, username, passwordHash, 0)
			redis.conn.Set(ctx, fmt.Sprintf("%s:su", username), "true", 0)

			b, err := Initialize(authOpts, log.DebugLevel, version)
			So(err, ShouldBeNil)

			tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)

			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)

			// Set a topic and check. Since the backend doesn't register superuser,
			// it should only be able to access that topic and nothing else even if superuser checks are not generally disabled.
			redis.conn.SAdd(ctx, username+":racls", "test/redis")

			So(b.disableSuperuser, ShouldBeTrue)

			aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeFalse)

			redis.Halt()
		})

		Convey("When superusers are enabled and the backend registers those checks, it'll grant everything on a superuser", func() {
			authOpts["backends"] = "redis"
			authOpts["redis_register"] = "user, superuser, acl"
			authOpts["check_prefix"] = "false"
			delete(authOpts, "prefixes")
			delete(authOpts, "disable_superuser")

			username := "redis_test1"
			password := username
			passwordHash := "PBKDF2$sha512$100000$hgodnayqjfs0AOCxvsU+Zw==$dfc4LBGmZ/wB128NOD48qF5fCS+r/bsjU+oCXgT3UksAik73vIkXcPFydtbJKoIgnepNXP9t+zGIaR5wyRmXaA=="

			redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
			assert.Nil(t, err)

			ctx := context.Background()

			// Insert a user to test auth.
			redis.conn.Set(ctx, username, passwordHash, 0)
			redis.conn.Set(ctx, fmt.Sprintf("%s:su", username), "true", 0)

			b, err := Initialize(authOpts, log.DebugLevel, version)
			So(err, ShouldBeNil)

			tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)

			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)

			// Set a topic and check an unregistered one, they should both pass.
			redis.conn.SAdd(ctx, username+":racls", "test/redis")

			aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			redis.Halt()
		})
	})

	Convey("With prefixes", t, func() {
		Convey("When superusers are enabled but the backend is not registered to check them, it'll skip to acls", func() {
			authOpts["backends"] = "redis"
			authOpts["redis_register"] = "user, acl"
			authOpts["check_prefix"] = "true"
			authOpts["prefixes"] = "redis"

			username := "redis_test1"
			password := username
			passwordHash := "PBKDF2$sha512$100000$hgodnayqjfs0AOCxvsU+Zw==$dfc4LBGmZ/wB128NOD48qF5fCS+r/bsjU+oCXgT3UksAik73vIkXcPFydtbJKoIgnepNXP9t+zGIaR5wyRmXaA=="

			redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
			assert.Nil(t, err)

			ctx := context.Background()

			// Insert a user to test auth.
			redis.conn.Set(ctx, username, passwordHash, 0)
			// Set it as superuser.
			redis.conn.Set(ctx, fmt.Sprintf("%s:su", username), "true", 0)

			b, err := Initialize(authOpts, log.DebugLevel, version)
			So(err, ShouldBeNil)

			tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)

			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)

			// Set a topic and check. Since the backend doesn't register superuser,
			// it should only be able to access that topic and nothing else even if superuser checks are not generally disabled.
			redis.conn.SAdd(ctx, username+":racls", "test/redis")

			So(b.disableSuperuser, ShouldBeFalse)

			aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeFalse)

			redis.Halt()
		})

		Convey("When superusers are disabled, even if the backend registers checks, it'll skip to acls", func() {
			authOpts["backends"] = "redis"
			authOpts["redis_register"] = "user, superuser, acl"
			authOpts["disable_superuser"] = "true"
			authOpts["check_prefix"] = "true"
			authOpts["prefixes"] = "redis"

			username := "redis_test1"
			password := username
			passwordHash := "PBKDF2$sha512$100000$hgodnayqjfs0AOCxvsU+Zw==$dfc4LBGmZ/wB128NOD48qF5fCS+r/bsjU+oCXgT3UksAik73vIkXcPFydtbJKoIgnepNXP9t+zGIaR5wyRmXaA=="

			redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
			assert.Nil(t, err)

			ctx := context.Background()

			// Insert a user to test auth.
			redis.conn.Set(ctx, username, passwordHash, 0)
			redis.conn.Set(ctx, fmt.Sprintf("%s:su", username), "true", 0)

			b, err := Initialize(authOpts, log.DebugLevel, version)
			So(err, ShouldBeNil)

			tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)

			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)

			// Set a topic and check. Since the backend doesn't register superuser,
			// it should only be able to access that topic and nothing else even if superuser checks are not generally disabled.
			redis.conn.SAdd(ctx, username+":racls", "test/redis")

			So(b.disableSuperuser, ShouldBeTrue)

			aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeFalse)

			redis.Halt()
		})

		Convey("When superusers are enabled and the backend registers those checks, it'll grant everything on a superuser", func() {
			authOpts["backends"] = "redis"
			authOpts["redis_register"] = "user, superuser, acl"
			authOpts["check_prefix"] = "true"
			authOpts["prefixes"] = "redis"
			delete(authOpts, "disable_superuser")

			username := "redis_test1"
			password := username
			passwordHash := "PBKDF2$sha512$100000$hgodnayqjfs0AOCxvsU+Zw==$dfc4LBGmZ/wB128NOD48qF5fCS+r/bsjU+oCXgT3UksAik73vIkXcPFydtbJKoIgnepNXP9t+zGIaR5wyRmXaA=="

			redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
			assert.Nil(t, err)

			ctx := context.Background()

			// Insert a user to test auth.
			redis.conn.Set(ctx, username, passwordHash, 0)
			redis.conn.Set(ctx, fmt.Sprintf("%s:su", username), "true", 0)

			b, err := Initialize(authOpts, log.DebugLevel, version)
			So(err, ShouldBeNil)

			tt1, err1 := b.AuthUnpwdCheck(username, password, clientid)

			So(err1, ShouldBeNil)
			So(tt1, ShouldBeTrue)

			// Set a topic and check an unregistered one, they should both pass.
			redis.conn.SAdd(ctx, username+":racls", "test/redis")

			aclCheck, err := b.AuthAclCheck(clientid, username, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			aclCheck, err = b.AuthAclCheck(clientid, username, "test/topic/1", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			redis.Halt()
		})

		Convey("When strip_prefix is true, the prefix will be stripped from the username prior to conducting checks", func() {
			authOpts["backends"] = "redis"
			authOpts["redis_register"] = "user, acl"
			authOpts["check_prefix"] = "true"
			authOpts["strip_prefix"] = "true"
			authOpts["prefixes"] = "redis"
			delete(authOpts, "disable_superuser")

			username := "redis_test1"
			stripUsername := "test1"
			password := username
			passwordHash := "PBKDF2$sha512$100000$hgodnayqjfs0AOCxvsU+Zw==$dfc4LBGmZ/wB128NOD48qF5fCS+r/bsjU+oCXgT3UksAik73vIkXcPFydtbJKoIgnepNXP9t+zGIaR5wyRmXaA=="

			redis, err := NewRedis(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, "redis"))
			assert.Nil(t, err)

			ctx := context.Background()

			// Insert a user to test auth.
			redis.conn.Set(ctx, stripUsername, passwordHash, 0)
			redis.conn.Set(ctx, fmt.Sprintf("%s:su", stripUsername), "true", 0)

			b, err := Initialize(authOpts, log.DebugLevel, version)
			So(err, ShouldBeNil)

			userCheck, err := b.AuthUnpwdCheck(username, password, clientid)

			So(err, ShouldBeNil)
			So(userCheck, ShouldBeTrue)

			redis.conn.SAdd(ctx, stripUsername+":racls", "test/redis")

			aclCheck, err := b.AuthAclCheck(clientid, stripUsername, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			userCheck, err = b.AuthUnpwdCheck(username, password, clientid)

			So(err, ShouldBeNil)
			So(userCheck, ShouldBeTrue)

			aclCheck, err = b.AuthAclCheck(clientid, stripUsername, "test/redis", 1)
			So(err, ShouldBeNil)
			So(aclCheck, ShouldBeTrue)

			redis.Halt()
		})
	})
}
