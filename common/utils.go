package common

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"

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

/*
* PBKDF2 passwords usage taken from github.com/brocaar/lora-app-server, comments included.
 */

// Generate the hash of a password for storage in the database.
// NOTE: We store the details of the hashing algorithm with the hash itself,
// making it easy to recreate the hash for password checking, even if we change
// the default criteria here.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func Hash(password string, saltSize int, iterations int, algorithm string, saltEncoding string, keylen int) (string, error) {
	// Generate a random salt value, 128 bits.
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", errors.Wrap(err, "read random bytes error")
	}

	return hashWithSalt(password, salt, iterations, algorithm, saltEncoding, keylen), nil
}

// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func hashWithSalt(password string, salt []byte, iterations int, algorithm string, saltEncoding string, keylen int) string {
	// Generate the hash.  This should be a little painful, adjust ITERATIONS
	// if it needs performance tweeking.  Greatly depends on the hardware.
	// NOTE: We store these details with the returned hash, so changes will not
	// affect our ability to do password compares.
	shaHash := sha512.New
	if algorithm == "sha256" {
		shaHash = sha256.New
	}
	hash := pbkdf2.Key([]byte(password), salt, iterations, keylen, shaHash)

	// Build up the parameters and hash into a single string so we can compare
	// other string to the same hash.  Note that the hash algorithm is hard-
	// coded here, as it is above.  Introducing alternate encodings must support
	// old encodings as well, and build this string appropriately.
	var buffer bytes.Buffer

	buffer.WriteString("PBKDF2$")
	buffer.WriteString(fmt.Sprintf("%s$", algorithm))
	buffer.WriteString(strconv.Itoa(iterations))
	buffer.WriteString("$")
	// Re-encode salt, using encoding supplied in saltEncoding param
	switch saltEncoding {
		case UTF8:
			buffer.WriteString(string(salt))
		case Base64:
			buffer.WriteString(base64.StdEncoding.EncodeToString(salt))
		default:
			log.Errorf("Supplied saltEncoding not supported: %s, defaulting to base64", saltEncoding)
			buffer.WriteString(base64.StdEncoding.EncodeToString(salt))
  	}
	buffer.WriteString("$")
	buffer.WriteString(base64.StdEncoding.EncodeToString(hash))
	//log.Debugf("Generated: ", buffer.String())
	return buffer.String()
}

// HashCompare verifies that passed password hashes to the same value as the
// passed passwordHash.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func HashCompare(password string, passwordHash string, saltEncoding string) bool {
	// Split the hash string into its parts.
	hashSplit := strings.Split(passwordHash, "$")
	// Check array is of expected length
	if len(hashSplit) != 5 {
		log.Errorf("HashCompare, invalid PBKDF2 hash supplied.")
		return false
	}
	// Get the iterations from PBKDF2 string
	iterations, err := strconv.Atoi(hashSplit[2])
	if err != nil {
		log.Errorf("Error getting number of iterations from PBKDF2 hash.")
		return false
	}
	// Convert salt to bytes, using encoding supplied in saltEncoding param
	salt := []byte{}
	switch saltEncoding {
		case UTF8:
			salt = []byte(hashSplit[3])
		case Base64:
			salt, err = base64.StdEncoding.DecodeString(hashSplit[3])
			if err != nil {
				log.Errorf("Error decoding supplied base64 salt.")
				return false
			}
		default:
			log.Errorf("Supplied saltEncoding not supported: %s, defaulting to base64", saltEncoding)
			salt, err = base64.StdEncoding.DecodeString(hashSplit[3])
			if err != nil {
				log.Errorf("Error decoding supplied base64 salt.")
				return false
			}
  	}
	// Work out key length, assumes base64 encoding
	hash, err := base64.StdEncoding.DecodeString(hashSplit[4])
	if err != nil {
		log.Errorf("Error decoding supplied base64 hash.")
		return false
	}
	keylen := len(hash)
	// Get the algorithm from PBKDF2 string
	algorithm := hashSplit[1]
	// Generate new PBKDF2 hash to compare against supplied PBKDF2 string
	newHash := hashWithSalt(password, salt, iterations, algorithm, saltEncoding, keylen)
	return newHash == passwordHash
}
