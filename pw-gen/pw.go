package main

import (
	"flag"
	"fmt"

	"github.com/iegomez/mosquitto-go-auth/hashing"
)

func main() {

	var hasher = flag.String("h", "pbkdf2", "hasher: pbkdf2, argon2 or bcrypt")
	var algorithm = flag.String("a", "sha512", "algorithm: sha256 or sha512")
	var iterations = flag.Int("i", 100000, "hash iterations: defaults to 100000 for pbkdf2, please set to a reasonable value for argon2")
	var password = flag.String("p", "", "password")
	var saltSize = flag.Int("s", 16, "salt size")
	var saltEncoding = flag.String("e", "base64", "salt encoding")
	var keylen = flag.Int("l", 0, "key length, recommended values are 32 for sha256 and 64 for sha512")
	var cost = flag.Int("c", 10, "bcrypt ost param")
	var memory = flag.Int("m", 4096, "memory for argon2 hash")
	var parallelism = flag.Int("pl", 2, "parallelism for argon2")

	flag.Parse()

	shaSize := *keylen

	if shaSize == 0 {
		switch *algorithm {
		case hashing.SHA256:
			shaSize = hashing.SHA256Size
		case hashing.SHA512:
			shaSize = hashing.SHA512Size
		default:
			fmt.Println("invalid password hash algorithm: ", *algorithm)
			return
		}
	}

	var hashComparer hashing.HashComparer

	switch *hasher {
	case hashing.Argon2IDOpt:
		hashComparer = hashing.NewArgon2IDHasher(*saltSize, *iterations, shaSize, uint32(*memory), uint8(*parallelism))
	case hashing.BcryptOpt:
		hashComparer = hashing.NewBcryptHashComparer(*cost)
	case hashing.Pbkdf2Opt:
		hashComparer = hashing.NewPBKDF2Hasher(*saltSize, *iterations, *algorithm, *saltEncoding, shaSize)
	default:
		fmt.Println("invalid hasher option: ", *hasher)
		return
	}

	pwHash, err := hashComparer.Hash(*password)
	if err != nil {
		fmt.Printf("error: %s", err)
	} else {
		fmt.Println(pwHash)
	}

}
