package backends

import (
	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestLDAP(t *testing.T) {

	username := "user"
	password := "test_user_pw"
	superuser_username := "superuser"
	testTopic := "test/topic"
	testClientId := "test_client"

	l, err := NewLDAP(map[string]string{
		"ldap_user_dn":                     "ou=people,dc=example,dc=org",
		"ldap_group_dn":                    "ou=groups,dc=example,dc=org",
		"ldap_bind_dn":                     "cn=mosquitto,ou=people,dc=example,dc=org",
		"ldap_bind_password":               "test_bind_pw",
		"ldap_user_filter":                 "(cn=%s)",
		"ldap_group_filter":                "(member=cn=%s,ou=people,dc=example,dc=org)",
		"ldap_superuser_filter":            "(&(cn=%s)(memberOf=cn=superuser,ou=groups,dc=example,dc=org))",
		"ldap_acl_topic_pattern_attribute": "mqttTopicPattern",
		"ldap_acl_acc_attribute":           "mqttTopicAcc",
	}, 5)

	if err != nil {
		t.Errorf("Error creating LDAP backend: %s", err)
		t.FailNow()
	}

	t.Cleanup(func() { l.Halt() })

	Convey("Given correct password/username, get user should return true", t, func() {
		authenticated, err := l.GetUser(username, password, testClientId)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)
	})

	Convey("Given incorrect password/username, get user should return false", t, func() {
		authenticated, err := l.GetUser(username, "wrong_password", testClientId)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

	Convey("Given correct username, get superuser should return true", t, func() {
		authenticated, err := l.GetSuperuser(superuser_username)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)

		Convey("But disabling superusers by removing superuri should now return false", func() {
			l.SuperuserFilter = ""
			superuser, err := l.GetSuperuser(username)
			So(err, ShouldBeNil)
			So(superuser, ShouldBeFalse)
		})
	})

	Convey("Given a username which isn't in the superuser group, get superuser should return false", t, func() {
		superuser, err := l.GetSuperuser(username)
		So(err, ShouldBeNil)
		So(superuser, ShouldBeFalse)
	})

	Convey("Given incorrect username, get superuser should return false", t, func() {
		authenticated, err := l.GetSuperuser("not_admin")
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

	Convey("Given correct topic, username, client id and acc, acl check should return true", t, func() {
		authenticated, err := l.CheckAcl(username, testTopic, testClientId, MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)
	})

	Convey("Given another topic matching the pattern, username, client id and acc, acl check should return true", t, func() {
		authenticated, err := l.CheckAcl(username, "test/other", testClientId, MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)
	})

	Convey("Given an acc that requires more privileges than the user has, check acl should return false", t, func() {
		authenticated, err := l.CheckAcl(username, testTopic, testClientId, MOSQ_ACL_WRITE)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

	Convey("Given a topic not present in acls, check acl should return false", t, func() {
		authenticated, err := l.CheckAcl(username, "fake/topic", testClientId, MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

}
