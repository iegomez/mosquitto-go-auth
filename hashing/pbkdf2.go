package hashing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
)

type pbkdf2Hasher struct {
	saltSize     int
	iterations   int
	algorithm    string
	saltEncoding string
	keyLen       int
}

func NewPBKDF2Hasher(saltSize int, iterations int, algorithm string, saltEncoding string, keylen int) HashComparer {
	return pbkdf2Hasher{
		saltSize:     saltSize,
		iterations:   iterations,
		algorithm:    algorithm,
		saltEncoding: preferredEncoding(saltEncoding),
		keyLen:       keylen,
	}
}

/*
* PBKDF2 methods are adapted from github.com/brocaar/chirpstack-application-server, some comments included.
 */

// Hash function reference may be found at https://github.com/brocaar/chirpstack-application-server/blob/master/internal/storage/user.go#L421.

// Generate the hash of a password for storage in the database.
// NOTE: We store the details of the hashing algorithm with the hash itself,
// making it easy to recreate the hash for password checking, even if we change
// the default criteria here.
func (h pbkdf2Hasher) Hash(password string) (string, error) {
	// Generate a random salt value with the given salt size.
	salt := make([]byte, h.saltSize)
	_, err := rand.Read(salt)

	// We need to ensure that salt doesn contain $, which is 36 in decimal.
	// So we check if there'sbyte that represents $ and change it with a random number in the range 0-35
	//// This is far from ideal, but should be good enough with a reasonable salt size.
	for i := 0; i < len(salt); i++ {
		if salt[i] == 36 {
			n, err := rand.Int(rand.Reader, big.NewInt(35))
			if err != nil {
				return "", fmt.Errorf("read random byte error: %s", err)
			}

			salt[i] = byte(n.Int64())
			break
		}
	}
	if err != nil {
		return "", fmt.Errorf("read random bytes error: %s", err)
	}

	return h.hashWithSalt(password, salt, h.iterations, h.algorithm, h.keyLen), nil
}

// HashCompare verifies that passed password hashes to the same value as the
// passed passwordHash.
// Reference: https://github.com/brocaar/chirpstack-application-server/blob/master/internal/storage/user.go#L458.
func (h pbkdf2Hasher) Compare(password string, passwordHash string) bool {
	hashSplit := strings.Split(passwordHash, "$")

	if len(hashSplit) != 5 {
		log.Errorf("invalid PBKDF2 hash supplied, expected length 5, got: %d", len(hashSplit))
		return false
	}

	algorithm := hashSplit[1]

	iterations, err := strconv.Atoi(hashSplit[2])
	if err != nil {
		log.Errorf("iterations error: %s", err)
		return false
	}

	var salt []byte
	switch h.saltEncoding {
	case UTF8:
		salt = []byte(hashSplit[3])
	default:
		salt, err = base64.StdEncoding.DecodeString(hashSplit[3])
		if err != nil {
			log.Errorf("base64 salt error: %s", err)
			return false
		}
	}

	hashedPassword, err := base64.StdEncoding.DecodeString(hashSplit[4])
	if err != nil {
		log.Errorf("base64 hash decoding error: %s", err)
		return false
	}

	keylen := len(hashedPassword)

	return passwordHash == h.hashWithSalt(password, salt, iterations, algorithm, keylen)
}

// Reference: https://github.com/brocaar/chirpstack-application-server/blob/master/internal/storage/user.go#L432.
func (h pbkdf2Hasher) hashWithSalt(password string, salt []byte, iterations int, algorithm string, keylen int) string {
	// Generate the hashed password. This should be a little painful, adjust ITERATIONS
	// if it needs performance tweeking.  Greatly depends on the hardware.
	// NOTE: We store these details with the returned hashed, so changes will not
	// affect our ability to do password compares.
	shaHash := sha512.New
	if algorithm == SHA256 {
		shaHash = sha256.New
	}

	hashed := pbkdf2.Key([]byte(password), salt, iterations, keylen, shaHash)

	var buffer bytes.Buffer

	buffer.WriteString("PBKDF2$")
	buffer.WriteString(fmt.Sprintf("%s$", algorithm))
	buffer.WriteString(strconv.Itoa(iterations))
	buffer.WriteString("$")

	switch h.saltEncoding {
	case UTF8:
		buffer.WriteString(string(salt))
	default:
		buffer.WriteString(base64.StdEncoding.EncodeToString(salt))
	}

	buffer.WriteString("$")
	buffer.WriteString(base64.StdEncoding.EncodeToString(hashed))

	return buffer.String()
}
