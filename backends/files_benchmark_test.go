package backends

import (
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
)

var files Files
var fbUser1 = "test1"

var fbClientID = "test_client"
var fbTestTopic1 = `test/topic/1`

func init() {
	var pwPath, _ = filepath.Abs("../test-files/passwords")
	var aclPath, _ = filepath.Abs("../test-files/acls")

	var authOpts = map[string]string{
		"password_path": pwPath,
		"acl_path":      aclPath,
	}

	files, _ = NewFiles(authOpts, log.ErrorLevel)
}

func BenchmarkFilesUser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		files.GetUser(fbUser1, fbUser1)
	}
}

func BenchmarkFilesSuperuser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		files.GetSuperuser(fbUser1)
	}
}

func BenchmarkFilesAcl(b *testing.B) {
	for n := 0; n < b.N; n++ {
		files.CheckAcl(fbUser1, fbTestTopic1, fbClientID, 2)
	}
}
