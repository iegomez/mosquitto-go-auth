package main

import (
	"flag"
	"fmt"

	"github.com/iegomez/mosquitto-go-auth/common"
)

func main() {

	var algorithm = flag.String("a", "sha512", "algorithm: sha256 or sha512")
	var HashIterations = flag.Int("i", 100000, "hash iterations")
	var password = flag.String("p", "", "password")
	var saltSize = flag.Int("s", 16, "salt size")

	flag.Parse()

	pwHash, err := common.Hash(*password, *saltSize, *HashIterations, *algorithm)
	if err != nil {
		fmt.Printf("error: %s\n", err)
	} else {
		fmt.Println(pwHash)
	}

}
