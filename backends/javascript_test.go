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
			userResponse := javascript.GetUser("correct", "good", "some-id")
			So(userResponse, ShouldBeTrue)

			userResponse = javascript.GetUser("correct", "bad", "some-id")
			So(userResponse, ShouldBeFalse)

			userResponse = javascript.GetUser("wrong", "good", "some-id")
			So(userResponse, ShouldBeFalse)
		})

		Convey("Superuser checks should work", func() {
			superuserResponse := javascript.GetSuperuser("admin")
			So(superuserResponse, ShouldBeTrue)

			superuserResponse = javascript.GetSuperuser("non-admin")
			So(superuserResponse, ShouldBeFalse)
		})

		Convey("ACL checks should work", func() {
			aclResponse := javascript.CheckAcl("correct", "test/topic", "id", 1)
			So(aclResponse, ShouldBeTrue)

			aclResponse = javascript.CheckAcl("incorrect", "test/topic", "id", 1)
			So(aclResponse, ShouldBeFalse)

			aclResponse = javascript.CheckAcl("correct", "bad/topic", "id", 1)
			So(aclResponse, ShouldBeFalse)

			aclResponse = javascript.CheckAcl("correct", "test/topic", "wrong-id", 1)
			So(aclResponse, ShouldBeFalse)

			aclResponse = javascript.CheckAcl("correct", "test/topic", "id", 2)
			So(aclResponse, ShouldBeFalse)
		})
	})
}
