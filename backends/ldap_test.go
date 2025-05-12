package backends

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/pkg/errors"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

type mockLDAPConn struct {
	searchFunc func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	bindFunc   func(username, password string) error
	closeFunc  func() error
}

func (m mockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.searchFunc != nil {
		return m.searchFunc(req)
	}
	return nil, errors.New("ldap mock search function not implemented")
}

func (m mockLDAPConn) Bind(username, password string) error {
	if m.bindFunc != nil {
		return m.bindFunc(username, password)
	}
	return errors.New("ldap mock bind function not implemented")
}

func (m mockLDAPConn) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestLDAP(t *testing.T) {

	testUsername := "test_user"
	testPassword := "test_password"
	testTopic := "test/topic"
	testTopicPattern := "test/+"
	testAcc := "1"
	testClientId := "test_client"

	l, _ := NewLDAPWithFactory(
		map[string]string{
			"ldap_base_dn":                     "dc=example,dc=com",
			"ldap_group_base_dn":               "ou=groups,dc=example,dc=com",
			"ldap_bind_dn":                     "uid=mosquitto,dc=example,dc=com",
			"ldap_bind_password":               "test_bind_password",
			"ldap_user_filter":                 "(uid=%s)",
			"ldap_superuser_filter":            "(&(uid=%s)(memberOf=superuser))",
			"ldap_acl_topic_pattern_attribute": "topic_pattern",
			"ldap_acl_acc_attribute":           "acc",
		},
		0,
		func(l LDAP) (LDAPClient, error) {
			return mockLDAPConn{
				searchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					if req.BaseDN == l.BaseDN && req.Filter == fmt.Sprintf(l.UserFilter, testUsername) {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{DN: fmt.Sprintf("uid=%s,%s", testUsername, l.BaseDN)},
							},
						}, nil
					}
					if req.BaseDN == l.BaseDN && req.Filter == fmt.Sprintf(l.SuperuserFilter, testUsername) {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{DN: fmt.Sprintf("uid=%s,%s", testUsername, l.BaseDN)},
							},
						}, nil
					}
					if req.BaseDN == l.GroupBaseDN && req.Filter == fmt.Sprintf(l.GroupFilter, testUsername) {
						return &ldap.SearchResult{
							Entries: []*ldap.Entry{
								{Attributes: []*ldap.EntryAttribute{
									{Name: l.AclTopicPatternAttribute, Values: []string{testTopicPattern}},
									{Name: l.AclAccAttribute, Values: []string{testAcc}},
								}},
							},
						}, nil
					}
					return &ldap.SearchResult{
						Entries: []*ldap.Entry{},
					}, nil
				},
				bindFunc: func(username, password string) error {
					if username == l.BindDN && password == l.BindPass {
						return nil
					}
					if username == fmt.Sprintf("uid=%s,%s", testUsername, l.BaseDN) && password == testPassword {
						return nil
					}
					return errors.New("bind failed")
				},
				closeFunc: nil,
			}, nil
		},
	)

	Convey("Given correct password/username, get user should return true", t, func() {
		authenticated, err := l.GetUser(testUsername, testPassword, testClientId)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)
	})

	Convey("Given incorrect password/username, get user should return false", t, func() {
		authenticated, err := l.GetUser(testUsername, "wrong_password", testClientId)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

	Convey("Given correct username, get superuser should return true", t, func() {
		authenticated, err := l.GetSuperuser(testUsername)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)

		Convey("But disabling superusers by removing superuri should now return false", func() {
			l.SuperuserFilter = ""
			superuser, err := l.GetSuperuser(testUsername)
			So(err, ShouldBeNil)
			So(superuser, ShouldBeFalse)
		})
	})

	Convey("Given incorrect username, get superuser should return false", t, func() {
		authenticated, err := l.GetSuperuser("not_admin")
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

	Convey("Given correct topic, username, client id and acc, acl check should return true", t, func() {
		authenticated, err := l.CheckAcl(testUsername, testTopic, testClientId, MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)
	})

	Convey("Given another topic matching the pattern, username, client id and acc, acl check should return true", t, func() {
		authenticated, err := l.CheckAcl(testUsername, "test/other", testClientId, MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeTrue)
	})

	Convey("Given an acc that requires more privileges than the user has, check acl should return false", t, func() {
		authenticated, err := l.CheckAcl(testUsername, testTopic, testClientId, MOSQ_ACL_WRITE)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

	Convey("Given a topic not present in acls, check acl should return false", t, func() {
		authenticated, err := l.CheckAcl(testUsername, "fake/topic", testClientId, MOSQ_ACL_READ)
		So(err, ShouldBeNil)
		So(authenticated, ShouldBeFalse)
	})

	Convey("matchMQTT should match mqtt topics correctly", t, func() {
		tests := []struct {
			pattern  string
			topic    string
			expected bool
		}{
			// Exact matches
			{"a/b/c", "a/b/c", true},
			{"a/b", "a/b", true},
			{"a", "a", true},

			{"a/b", "a/x", false},
			{"a/b", "x/b", false},

			// Single-level wildcard +
			{"a/+/c", "a/b/c", true},
			{"a/+/c", "a/x/c", true},
			{"+/+/+", "a/b/c", true},
			{"+/b/+", "a/b/c", true},
			{"a/b/+", "a/b/c", true},
			{"+", "a", true},

			{"a/+/c", "a/x/x", false},

			// Wrong segment count with +
			{"a/+/c", "a/c", false},
			{"a/+/c", "a/b/c/d", false},
			{"+/+", "a", false},
			{"+/+", "a/b/c", false},

			// Multi-level wildcard #
			{"a/b/#", "a/b", true},
			{"a/b/#", "a/b/c", true},
			{"a/b/#", "a/b/c/d/e", true},
			{"#", "a", true},
			{"#", "a/b/c", true},
			{"#", "/", true},
			{"#", "//", true},

			{"a/b/#", "a", false},
			{"a/b/#", "a/x/c", false},

			// # cannot match middle segments
			{"a/#/c", "a/b/c", false},

			// Pattern longer than topic
			{"a/b/c/d", "a/b/c", false},
			{"a/b/+", "a/b", false},

			// Topic longer than pattern
			{"a/b", "a/b/c", false},
			{"a/b/c", "a/b/c/d", false},
			{"a/b/+", "a/b/c/d", false},

			// Empty topic and pattern
			{"", "", true},
			{"#", "", true},
			{"+", "", true},

			{"", "a", false},

			// Trailing slashes
			{"a/b/", "a/b/", true},

			{"a/b", "a/b/", false},
			{"a/b/", "a/b", false},

			// Topic with empty segments
			{"a//c", "a//c", true},
			{"a/+/c", "a//c", true},
		}

		for i, test := range tests {
			Convey(fmt.Sprintf("#%d: matchMQTT(%s, %s)", i, test.topic, test.pattern), func() {
				result := matchMQTT(test.topic, test.pattern)
				if result != test.expected {
					fmt.Printf("\nFAILED test #%d: topic=%q pattern=%q → got=%v, expected=%v\n", i, test.topic, test.pattern, result, test.expected)
				}
				So(result, ShouldEqual, test.expected)
			})
		}
	})

}
