package backends

import (
	"testing"

	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestJavascript(t *testing.T) {
	authOpts := make(map[string]string)

	authOpts["js_user_script_path"] = "../test-files/js/user_script.js"
	authOpts["js_superuser_script_path"] = "../test-files/js/superuser_script.js"
	authOpts["js_acl_script_path"] = "../test-files/js/acl_script.js"

	Convey("When constructing a Javascript backend", t, func() {
		Convey("It returns error if there's a missing option", func() {
			badOpts := make(map[string]string)

			badOpts["js_user_script"] = authOpts["js_user_script"]
			badOpts["js_superuser_script"] = authOpts["js_superuser_script"]

			_, err := NewJavascript(badOpts, log.DebugLevel)
			So(err, ShouldNotBeNil)
		})

		Convey("It returns error if a script can't be opened", func() {
			badOpts := make(map[string]string)

			badOpts["js_user_script"] = authOpts["js_user_script"]
			badOpts["js_superuser_script"] = authOpts["js_superuser_script"]
			badOpts["js_acl_script_path"] = "../test-files/js/nothing_here.js"

			_, err := NewJavascript(badOpts, log.DebugLevel)
			So(err, ShouldNotBeNil)
		})

		javascript, err := NewJavascript(authOpts, log.DebugLevel)
		So(err, ShouldBeNil)

		Convey("User checks should work", func() {
			userResponse, err := javascript.GetUser("correct", "good", "some-id")
			So(err, ShouldBeNil)
			So(userResponse, ShouldBeTrue)

			userResponse, err = javascript.GetUser("correct", "bad", "some-id")
			So(err, ShouldBeNil)
			So(userResponse, ShouldBeFalse)

			userResponse, err = javascript.GetUser("wrong", "good", "some-id")
			So(err, ShouldBeNil)
			So(userResponse, ShouldBeFalse)
		})

		Convey("Superuser checks should work", func() {
			superuserResponse, err := javascript.GetSuperuser("admin")
			So(err, ShouldBeNil)
			So(superuserResponse, ShouldBeTrue)

			superuserResponse, err = javascript.GetSuperuser("non-admin")
			So(err, ShouldBeNil)
			So(superuserResponse, ShouldBeFalse)
		})

		Convey("ACL checks should work", func() {
			aclResponse, err := javascript.CheckAcl("correct", "test/topic", "id", 1)
			So(err, ShouldBeNil)
			So(aclResponse, ShouldBeTrue)

			aclResponse, err = javascript.CheckAcl("incorrect", "test/topic", "id", 1)
			So(err, ShouldBeNil)
			So(aclResponse, ShouldBeFalse)

			aclResponse, err = javascript.CheckAcl("correct", "bad/topic", "id", 1)
			So(err, ShouldBeNil)
			So(aclResponse, ShouldBeFalse)

			aclResponse, err = javascript.CheckAcl("correct", "test/topic", "wrong-id", 1)
			So(err, ShouldBeNil)
			So(aclResponse, ShouldBeFalse)

			aclResponse, err = javascript.CheckAcl("correct", "test/topic", "id", 2)
			So(err, ShouldBeNil)
			So(aclResponse, ShouldBeFalse)
		})
	})
}
