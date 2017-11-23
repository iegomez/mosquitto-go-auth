package main

import "C"

import "fmt"

var jsonJwtOpts []string
var pgOpts []string
var redisOpts []string

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int) {
	fmt.Printf("authOpts: %v\n%v\n", keys, values)
}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password string) bool {
	return true
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic string, acc int) bool {
	return true
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

func main() {}
