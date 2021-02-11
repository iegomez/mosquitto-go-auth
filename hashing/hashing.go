package hashing

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// algorithms
	SHA512     = "sha512"
	SHA256     = "sha256"
	SHA256Size = 32
	SHA512Size = 64

	// encodings
	UTF8   = "utf-8"
	Base64 = "base64"

	// hashers
	Pbkdf2Opt   = "pbkdf2"
	Argon2IDOpt = "argon2id"
	BcryptOpt   = "bcrypt"

	// defaults
	defaultBcryptCost = 10

	defaultArgon2IDSaltSize           = 16
	defaultArgon2IDMemory      uint32 = 4096
	defaultArgon2IDIterations         = 3
	defaultArgon2IDParallelism uint8  = 2
	defaultArgon2IDKeyLen             = 32

	defaultPBKDF2SaltSize   = 16
	defaultPBKDF2Iterations = 100000
	defaultPBKDF2KeyLen     = 32
	defaultPBKDF2Algorithm  = SHA512
)

var saltEncodings = map[string]struct{}{
	UTF8:   {},
	Base64: {},
}

type HashComparer interface {
	Hash(password string) (string, error)
	Compare(password, passwordHash string) bool
}

func preferredEncoding(saltEncoding string) string {
	preferredEncoding := Base64
	if _, ok := saltEncodings[saltEncoding]; ok {
		preferredEncoding = saltEncoding
	}
	return preferredEncoding
}

// Process hash opts:

// Empty backend: use whatever plugin wise hashing options are present by returning whole opts.
// Backend present: check if there's a backend_hasher option:
// 	- Yes: return a new map with whatever hashing options are present for the given backend and hasher
//		   (defaults will be used for missing options).
//	- No: use whatever plugin wise hashing options are present by returning whole opts.
func processHashOpts(authOpts map[string]string, backend string) map[string]string {

	// Return authOpts if no backend given.
	if backend == "" {
		return authOpts
	}
	// Return authOpts if no hasher was passed for the backend.
	if _, ok := authOpts[fmt.Sprintf("%s_hasher", backend)]; !ok {
		return authOpts
	}
	// Extract specific backend options.
	hashOpts := make(map[string]string)
	for k, v := range authOpts {
		if strings.Contains(k, backend) {
			hashOpts[strings.TrimPrefix(k, backend+"_")] = v
		}
	}
	return hashOpts
}

// NewHasher returns a hasher depending on the given options.
func NewHasher(authOpts map[string]string, backend string) HashComparer {
	opts := processHashOpts(authOpts, backend)

	switch opts["hasher"] {
	case BcryptOpt:
		log.Debugf("new hasher: %s", BcryptOpt)
		cost, err := strconv.ParseInt(opts["hasher_cost"], 10, 64)
		if err != nil {
			return NewBcryptHashComparer(defaultBcryptCost)
		}
		return NewBcryptHashComparer(int(cost))
	case Argon2IDOpt:
		log.Debugf("new hasher: %s", Argon2IDOpt)
		saltSize := defaultArgon2IDSaltSize
		if v, err := strconv.ParseInt(opts["hasher_salt_size"], 10, 64); err == nil {
			saltSize = int(v)
		}
		memory := defaultArgon2IDMemory
		if v, err := strconv.ParseUint(opts["hasher_memory"], 10, 32); err == nil {
			memory = uint32(v)
		}
		iterations := defaultArgon2IDIterations
		if v, err := strconv.ParseInt(opts["hasher_iterations"], 10, 64); err == nil {
			iterations = int(v)
		}
		parallelism := defaultArgon2IDParallelism
		if v, err := strconv.ParseUint(opts["hasher_parallelism"], 10, 8); err == nil {
			parallelism = uint8(v)
		}
		keyLen := defaultArgon2IDKeyLen
		if v, err := strconv.ParseInt(opts["hasher_keylen"], 10, 64); err == nil {
			keyLen = int(v)
		}
		return NewArgon2IDHasher(saltSize, iterations, keyLen, memory, parallelism)
	case Pbkdf2Opt:
		log.Debugf("new hasher: %s", Pbkdf2Opt)
	default:
		log.Warnln("unknown or empty hasher, defaulting to PBKDF2")
	}

	saltSize := defaultPBKDF2SaltSize
	if v, err := strconv.ParseInt(opts["hasher_salt_size"], 10, 64); err == nil {
		saltSize = int(v)
	}

	iterations := defaultPBKDF2Iterations
	if v, err := strconv.ParseInt(opts["hasher_iterations"], 10, 64); err == nil {
		iterations = int(v)
	}
	keyLen := defaultPBKDF2KeyLen
	if v, err := strconv.ParseInt(opts["hasher_keylen"], 10, 64); err == nil {
		keyLen = int(v)
	}
	algorithm := defaultPBKDF2Algorithm
	if opts["hasher_algorithm"] == "sha256" {
		algorithm = SHA256
	}

	saltEncoding := opts["hasher_salt_encoding"]
	return NewPBKDF2Hasher(saltSize, iterations, algorithm, saltEncoding, keyLen)

	return nil
}
