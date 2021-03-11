package backends

import (
	"testing"

	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCustomPlugin(t *testing.T) {
	// There's not much to test other than it loads and calls the functions as expected.
	authOpts := map[string]string{
		"plugin_path": "../plugin/plugin.so",
	}

	username := "user"
	password := "password"
	clientid := "clientid"
	topic := "topic"
	acc := int32(1)

	Convey("Loading  dummy plugin should work", t, func() {
		plugin, err := NewCustomPlugin(authOpts, log.DebugLevel)
		So(err, ShouldBeNil)

		userCheck, err := plugin.GetUser(username, password, clientid)
		So(err, ShouldBeNil)
		So(userCheck, ShouldBeFalse)

		superuserCheck, err := plugin.getSuperuser(username)
		So(err, ShouldBeNil)
		So(superuserCheck, ShouldBeFalse)

		aclCheck, err := plugin.CheckAcl(username, topic, clientid, acc)
		So(err, ShouldBeNil)
		So(aclCheck, ShouldBeFalse)

		name := plugin.GetName()
		So(name, ShouldEqual, "Custom plugin")
	})
}
