package main

import "C"

import (
	"log"
	"strings"
)

var allowedBackends = map[string]bool{
	"postgres": true,
	"jwt":      true,
	"redis":    true,
	"http":     true,
	"files":    true,
}
var backends []string
var authOpts map[string]string

//export AuthPluginInit
func AuthPluginInit(keys []string, values []string, authOptsNum int) {
	log.Printf("authOpts: %v\n%v\n", keys, values)
	//First, get backends
	backendsOk := false
	authOpts = make(map[string]string)
	for i := 0; i < authOptsNum; i++ {
		if keys[i] == "backends" {
			backends = strings.Split(strings.Replace(keys[i], " ", "", -1), ",")
			if len(backends) > 0 {
				backendsCheck := true
				for backend := range backends {
					if _, ok := allowedBackends[backend]; !ok {
						backendsCheck = false
					}
				}
				backendsOk = backendsCheck
			}
		} else {
			authOpts[keys[i]] = values[i]
		}
	}

	//Log and end program if backends are wrong
	if !backendsOk {
		log.Fatal("backends error")
	}

	log.Printf("authOpts are: %v\n", authOpts)

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
