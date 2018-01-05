package main

import (
	log "github.com/sirupsen/logrus"
)

func Init(authOpts map[string]string, logLevel log.Level) error {
	//Initialize your plugin with the necessary options
	log.Infof("Plugin initialized!")
	log.Infof("Received %d options.", len(authOpts))
	return nil
}

func GetUser(username, password string) bool {
	log.Infof("Checking get user with custom plugin.")
	return false
}

func GetSuperuser(username string) bool {
	log.Infof("Checking get superuser with custom plugin.")
	return false
}

func CheckAcl(username, topic, clientid string, acc int) bool {
	log.Infof("Checking acl with custom plugin.")
	return false
}

func GetName() string {
	return "Custom plugin"
}
