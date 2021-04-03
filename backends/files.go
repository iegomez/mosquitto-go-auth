package backends

import (
	"strings"

	"github.com/iegomez/mosquitto-go-auth/backends/files"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Files hols a static failes checker.
type Files struct {
	checker *files.Checker
}

// NewFiles initializes a files backend.
func NewFiles(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (*Files, error) {

	log.SetLevel(logLevel)

	/*
		It is an error for the Files backend not to have a passwords file, but it is not for the underlying
		static files checker since it may be used in JWT. Thus, we need to check for the option here before
		building our checker.
	*/

	pwRegistered := strings.Contains(authOpts["files_register"], "user")

	pwPath, ok := authOpts["files_password_path"]

	if pwRegistered && (!ok || pwPath == "") {
		return nil, errors.New("missing passwords file path")
	}

	var checker, err = files.NewChecker(authOpts["backends"], authOpts["files_password_path"], authOpts["files_acl_path"], logLevel, hasher)
	if err != nil {
		return nil, err
	}

	return &Files{
		checker: checker,
	}, nil
}

// GetUser checks that user exists and password is correct.
func (o *Files) GetUser(username, password, clientid string) (bool, error) {
	return o.checker.GetUser(username, password, clientid)
}

// GetSuperuser returns false for files backend.
func (o *Files) GetSuperuser(username string) (bool, error) {
	return false, nil
}

// CheckAcl checks that the topic may be read/written by the given user/clientid.
func (o *Files) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	return o.checker.CheckAcl(username, topic, clientid, acc)
}

// GetName returns the backend's name
func (o *Files) GetName() string {
	return "Files"
}

// Halt cleans up Files backend.
func (o *Files) Halt() {
	o.checker.Halt()
}
