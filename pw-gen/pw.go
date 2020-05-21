package main

import (
	"flag"
	"fmt"

	"github.com/iegomez/mosquitto-go-auth/common"
)

func main() {

	const (
		sha256Size = 32
		sha512Size = 64
	)

	var algorithm = flag.String("a", "sha512", "algorithm: sha256 or sha512")
	var HashIterations = flag.Int("i", 100000, "hash iterations")
	var password = flag.String("p", "", "password")
	var saltSize = flag.Int("s", 16, "salt size")
	var saltEncoding = flag.String("e", "base64", "salt encoding")
	var keylen = flag.Int("l", 0, "key length, recommend 32 for sha256 and 64 for sha512")

	flag.Parse()

	// If supplied keylength is 0, use pre-defined key length
	shaSize := *keylen
	if shaSize == 0 {
		switch *algorithm {
		case "sha265":
			shaSize = sha256Size
		case "sha512":
			shaSize = sha512Size
		default:
			fmt.Println("Invalid password hash algorithm:", *algorithm)
			return
		}
	}

	pwHash, err := common.Hash(*password, *saltSize, *HashIterations, *algorithm, *saltEncoding, shaSize)
	if err != nil {
		fmt.Printf("error: %s", err)
	} else {
		fmt.Println(pwHash)
	}

}
