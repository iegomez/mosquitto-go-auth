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
	var saltEncoding = flag.String("e", "base64", "salt encoding")
	var keylen = flag.Int("l", 64, "key length, reccommend 32 for sha256 and 64 for sha512")

	flag.Parse()

	pwHash, err := common.Hash(*password, *saltSize, *HashIterations, *algorithm, *saltEncoding, *keylen)
	if err != nil {
		fmt.Printf("error: %s\n", err)
	} else {
		fmt.Println(pwHash)
	}

}
