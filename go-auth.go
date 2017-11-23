package main

import "C"

import "fmt"
import "unsafe"

var jsonJwtOpts []string
var pgOpts []string
var redisOpts []string

//export AuthPluginInit
func AuthPluginInit(authOpts map[string]string, authOptsNum int) {
	fmt.Printf("authOpts: %v\n", unsafe.Pointer(&authOpts))
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
