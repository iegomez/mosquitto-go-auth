package backends

import (
	"path/filepath"
	"testing"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestFilesBackend(t *testing.T) {
	// The bulk of files testing is done in the internal files checker, we'll just check obvious initialization and defaults.

	authOpts := make(map[string]string)
	logLevel := log.DebugLevel
	hasher := hashing.NewHasher(authOpts, "files")

	Convey("When files backend is set, missing passwords path should make NewFiles fail when registered to check users", t, func() {
		authOpts["backends"] = "files"
		authOpts["files_register"] = "user"

		_, err := NewFiles(authOpts, logLevel, hasher)
		So(err, ShouldNotBeNil)
	})

	Convey("When files backend is set, missing passwords path should not make NewFiles fail when not registered to check users", t, func() {
		authOpts["backends"] = "files"
		delete(authOpts, "files_register")

		_, err := NewFiles(authOpts, logLevel, hasher)
		So(err, ShouldBeNil)
	})

	Convey("When passwords path is given, NewFiles should succeed", t, func() {
		pwPath, err := filepath.Abs("../test-files/passwords")
		So(err, ShouldBeNil)

		authOpts["backends"] = "files"
		authOpts["files_register"] = "user"
		authOpts["files_password_path"] = pwPath

		_, err = NewFiles(authOpts, logLevel, hasher)
		So(err, ShouldBeNil)
	})

	Convey("When Files is only registered to check acls and there are no rules for the tested user", t, func() {
		aclPath, err := filepath.Abs("../test-files/acls-only")
		So(err, ShouldBeNil)

		authOpts["backends"] = "files"
		authOpts["files_register"] = "acl"
		authOpts["files_acl_path"] = aclPath
		delete(authOpts, "files_password_path")

		f, err := NewFiles(authOpts, logLevel, hasher)
		So(err, ShouldBeNil)

		granted, err := f.CheckAcl("some-user", "any/topic", "client-id", 1)
		So(err, ShouldBeNil)
		So(granted, ShouldBeTrue)

		granted, err = f.CheckAcl("test1", "any/topic", "client-id", 1)
		So(err, ShouldBeNil)
		So(granted, ShouldBeFalse)
	})

	Convey("With acls only test case", t, func() {
		aclPath, err := filepath.Abs("../test-files/acls-read-only")
		So(err, ShouldBeNil)

		So(err, ShouldBeNil)

		authOpts["backends"] = "files"
		authOpts["files_register"] = "acl"
		authOpts["files_acl_path"] = aclPath
		delete(authOpts, "files_password_path")

		f, err := NewFiles(authOpts, logLevel, hasher)
		So(err, ShouldBeNil)

		granted, err := f.CheckAcl("some-user", "clients/wrong-topic", "client-id", 1)
		So(err, ShouldBeNil)
		So(granted, ShouldBeFalse)

		granted, err = f.CheckAcl("some-user", "clients/wrong-topic", "client-id", 2)
		So(err, ShouldBeNil)
		So(granted, ShouldBeFalse)

		granted, err = f.CheckAcl("some-user", "clients/topic", "client-id", 2)
		So(err, ShouldBeNil)
		So(granted, ShouldBeFalse)

		granted, err = f.CheckAcl("some-user", "clients/topic", "client-id", 1)
		So(err, ShouldBeNil)
		So(granted, ShouldBeTrue)

		granted, err = f.CheckAcl("some-user", "clients/client-id", "client-id", 2)
		So(err, ShouldBeNil)
		So(granted, ShouldBeTrue)
	})
}
