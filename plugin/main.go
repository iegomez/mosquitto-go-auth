package main

import (
	log "github.com/sirupsen/logrus"
)

func Init(authOpts map[string]string, logLevel log.Level) error {
	//Initialize your plugin with the necessary options
	log.Infof("customPlugin initialized!")
	log.Debugf("Received %d options.", len(authOpts))
	return nil
}

func GetUser(username, password, clientid string) (bool, error) {
	log.Debugf("Checking get user with custom plugin.")
	return false, nil
}

func GetSuperuser(username string) (bool, error) {
	log.Debugf("Checking get superuser with custom plugin.")
	return false, nil
}

func CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	log.Debugf("Checking acl with custom plugin.")
	return false, nil
}

func GetName() string {
	return "Custom plugin"
}

func Halt() {
	//Do whatever cleanup is needed.
}
