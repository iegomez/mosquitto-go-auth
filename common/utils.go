package common

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"

	"github.com/jmoiron/sqlx"
)

// Declare the valid encodings for validation.
const (
    UTF8 = "utf-8"
    Base64 = "base64"
)

// OpenDatabase opens the database and performs a ping to make sure the
// database is up.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func OpenDatabase(dsn, engine string) (*sqlx.DB, error) {

	db, err := sqlx.Open(engine, dsn)
	if err != nil {
		return nil, errors.Wrap(err, "database connection error")
	}

	for {
		if err = db.Ping(); err != nil {
			log.Errorf("ping database error, will retry in 2s: %s", err)
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}

	return db, nil
}

func TopicsMatch(savedTopic, givenTopic string) bool {
	return givenTopic == savedTopic || match(strings.Split(savedTopic, "/"), strings.Split(givenTopic, "/"))
}

func match(route []string, topic []string) bool {
	if len(route) == 0 {
		if len(topic) == 0 {
			return true
		}
		return false
	}

	if len(topic) == 0 {
		if route[0] == "#" {
			return true
		}
		return false
	}

	if route[0] == "#" {
		return true
	}

	if (route[0] == "+") || (route[0] == topic[0]) {
		return match(route[1:], topic[1:])
	}

	return false
}

// adapted from https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
func Hash(password string, saltSize int, iterations int, algorithm string, saltEncoding string, keylen int) (string, error) {
	// Here commence the hackery - to prove the concept of generating and validating argon2id hashes with hard-coded params
	saltSize = 16
	var memory uint32 = 4096
	iterations = 3
	var parallelism uint8 = 2
	keylen = 32
	// These hard-coded params above may need to be tuned - should they be passed in, configured as auth_opts or ...?
	// see https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4 for tuning considerations

	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", errors.Wrap(err, "read random bytes error")
	}

	return hashWithSalt(password, salt, memory, iterations, parallelism, keylen), nil
}

// I hope hashWithSalt is only called by the above Hash function because I've changed its signature! compiler seems happy...
func hashWithSalt(password string, salt []byte, memory uint32, iterations int, parallelism uint8, keylen int) string {
	// We want a hash of type argon2id so use the IDKey function- see https://godoc.org/golang.org/x/crypto/argon2
	hash := argon2.IDKey([]byte(password), salt, uint32(iterations), memory, parallelism, uint32(keylen))

	// Base64 encode the salt and hashed password
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string using the standard encoded hash representation
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)

	//log.Debugf("Generated: ", encodedHash())
	return encodedHash
}
// HashCompare verifies that passed password hashes to the same value as the
// passed passwordHash.
func HashCompare(password string, passwordHash string, saltEncoding string) bool {
	// Split the hash string into its parts.
	hashSplit := strings.Split(passwordHash, "$")

	// Check array is of expected length
	if len(hashSplit) != 6 {
		log.Errorf("Invalid hash supplied, not 6 elements.")
		return false
	}

	// now we go over hashSplit array bit by bit validating it and loading up our params
	var version int
	_, err := fmt.Sscanf(hashSplit[2], "v=%d", &version)

	if err != nil {
		log.Errorf("something went wrong with the version")
		return false
	}

	if version != argon2.Version {
		log.Errorf("wrong argon2 version")
		return false
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(hashSplit[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)

	salt, err := base64.RawStdEncoding.DecodeString(hashSplit[4])
	if err != nil {
		log.Errorf("something went wrong with the salt extraction")
		return false
	}

	extractedHash, err := base64.RawStdEncoding.DecodeString(hashSplit[5])
	if err != nil {
		log.Errorf("something went wrong with the hash extraction")
		return false
	}

	keylen := uint32(len(extractedHash))

	//so now we use all the parameters extracted from the supplied hash to compute a similar hash for password under test
	newHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(keylen))

	// subtle compare method used rather than a simple comparison to mitigate against timing attacks
	if subtle.ConstantTimeCompare(newHash, extractedHash) == 1 {
		return true
	}
	return false
}
