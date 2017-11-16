package main

import "C"

var jsonJwtOpts []string
var pgOpts []string
var redisOpts []string

//export AuthPluginInit
func AuthPluginInit(authOpts []string, authOptsNum int) {

}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password string) bool {

}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) bool {

}

//export AuthPskKeyGet()
func AuthPskKeyGet() {

}

func main() {}
