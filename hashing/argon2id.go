package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"
)

type argon2IDHasher struct {
	saltSize    int
	iterations  int
	keyLen      int
	memory      uint32
	parallelism uint8
}

func NewArgon2IDHasher(saltSize int, iterations int, keylen int, memory uint32, parallelism uint8) HashComparer {
	return argon2IDHasher{
		saltSize:    saltSize,
		iterations:  iterations,
		keyLen:      keylen,
		memory:      memory,
		parallelism: parallelism,
	}
}

// Hash generates a hashed password using Argon2ID.
func (h argon2IDHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", errors.Wrap(err, "read random bytes error")
	}

	return h.hashWithSalt(password, salt, h.memory, h.iterations, h.parallelism, h.keyLen), nil
}

// Compare checks that an argon2 generated password matches the password hash.
func (h argon2IDHasher) Compare(password string, passwordHash string) bool {
	hashSplit := strings.Split(passwordHash, "$")

	if hashSplit[1] != "argon2id" {
		log.Errorf("unknown hash format: %s", hashSplit[1])
	}

	if len(hashSplit) != 6 {
		log.Errorf("invalid hash supplied, expected 6 elements, got: %d", len(hashSplit))
		return false
	}

	version, err := strconv.ParseInt(strings.TrimPrefix(hashSplit[2], "v="), 10, 32)
	if err != nil {
		log.Errorf("argon2id version parse error: %s", err)
		return false
	}

	if version != argon2.Version {
		log.Errorf("unknown argon2id version: %d", version)
		return false
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(hashSplit[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		log.Errorf("argon2id parameters parse error: %s", err)
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(hashSplit[4])
	if err != nil {
		log.Errorf("base64 salt error: %s", err)
		return false
	}

	extractedHash, err := base64.RawStdEncoding.DecodeString(hashSplit[5])
	if err != nil {
		log.Errorf("argon2id decoding error: %s", err)
		return false
	}

	keylen := uint32(len(extractedHash))
	newHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keylen)

	if subtle.ConstantTimeCompare(newHash, extractedHash) == 1 {
		return true
	}

	return false
}

func (h argon2IDHasher) hashWithSalt(password string, salt []byte, memory uint32, iterations int, parallelism uint8, keylen int) string {

	hashedPassword := argon2.IDKey([]byte(password), salt, uint32(iterations), memory, parallelism, uint32(keylen))

	b64salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hashedPassword)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.memory, h.iterations, h.parallelism, b64salt, b64Hash)
}
