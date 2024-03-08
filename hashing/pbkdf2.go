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

func NewPBKDF2Hasher(saltSize int, iterations int, algorithm string, saltEncoding string, keyLen int) HashComparer {
	return pbkdf2Hasher{
		saltSize:     saltSize,
		iterations:   iterations,
		algorithm:    algorithm,
		saltEncoding: preferredEncoding(saltEncoding),
		keyLen:       keyLen,
	}
}

/*
* PBKDF2 methods are adapted from github.com/brocaar/chirpstack-application-server, some comments included.
 */

// Hash function generates a hash of the supplied password. The hash
// can then be stored directly in the database. The return hash will
// contain options according to the PHC String format found at
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
func (h pbkdf2Hasher) Hash(password string) (string, error) {
	// Generate a random salt value with the given salt size.
	salt := make([]byte, h.saltSize)
	_, err := rand.Read(salt)

	// We need to ensure that salt doesn't contain $, which is 36 in decimal.
	// So we check if there's byte that represents $ and change it with a random number in the range 0-35
	// // This is far from ideal, but should be good enough with a reasonable salt size.
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

// Compare verifies that passed password hashes to the same value as the
// passed passwordHash.
// Reference: https://github.com/brocaar/chirpstack-application-server/blob/master/internal/storage/user.go#L458.
// Parsing reference: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
func (h pbkdf2Hasher) Compare(password string, passwordHash string) bool {
	hashSplit := h.getFields(passwordHash)

	var (
		err            error
		algorithm      string
		paramString    string
		hashedPassword []byte
		salt           []byte
		iterations     int
		keyLen         int
	)
	if hashSplit[0] == "PBKDF2" {
		algorithm = hashSplit[1]
		iterations, err = strconv.Atoi(hashSplit[2])
		if err != nil {
			log.Errorf("iterations error: %s", err)
			return false
		}

		switch h.saltEncoding {
		case UTF8:
			salt = []byte(hashSplit[3])
		default:
			var err error
			salt, err = base64.StdEncoding.DecodeString(hashSplit[3])
			if err != nil {
				log.Errorf("base64 salt error: %s", err)
				return false
			}
		}

		hashedPassword, err = base64.StdEncoding.DecodeString(hashSplit[4])
		if err != nil {
			log.Errorf("base64 hash decoding error: %s", err)
			return false
		}
		keyLen = len(hashedPassword)

	} else if hashSplit[0] == "pbkdf2-sha512" {
		algorithm = "sha512"
		paramString = hashSplit[1]

		opts := strings.Split(paramString, ",")
		for _, opt := range opts {
			parts := strings.Split(opt, "=")
			for i := 0; i < len(parts); i += 2 {
				key := parts[i]
				val := parts[i+1]
				switch key {
				case "i":
					iterations, _ = strconv.Atoi(val)
				case "l":
					keyLen, _ = strconv.Atoi(val)
				default:
					log.Errorf("unknown options key (\"%s\")", key)
					return false
				}
			}
		}

		switch h.saltEncoding {
		case UTF8:
			salt = []byte(hashSplit[2])
		default:
			var err error
			salt, err = base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(hashSplit[2])
			if err != nil {
				log.Errorf("base64 salt error: %s", err)
				return false
			}
		}

		hashedPassword, err = base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(hashSplit[3])
	} else {
		log.Errorf("invalid PBKDF2 hash supplied, unrecognized format \"%s\"", hashSplit[0])
		return false
	}

	newHash := h.hashWithSalt(password, salt, iterations, algorithm, keyLen)
	hashSplit = h.getFields(newHash)
	newHashedPassword, err := base64.StdEncoding.DecodeString(hashSplit[4])
	if err != nil {
		log.Errorf("base64 salt error: %s", err)
		return false
	}

	return h.compareBytes(hashedPassword, newHashedPassword)
}

func (h pbkdf2Hasher) compareBytes(a, b []byte) bool {
	for i, x := range a {
		if b[i] != x {
			return false
		}
	}
	return true
}

func (h pbkdf2Hasher) getFields(passwordHash string) []string {
	hashSplit := strings.FieldsFunc(passwordHash, func(r rune) bool {
		switch r {
		case '$':
			return true
		default:
			return false
		}
	})
	return hashSplit
}

// Reference: https://github.com/brocaar/chirpstack-application-server/blob/master/internal/storage/user.go#L432.
func (h pbkdf2Hasher) hashWithSalt(password string, salt []byte, iterations int, algorithm string, keylen int) string {
	// Generate the hashed password. This should be a little painful, adjust ITERATIONS
	// if it needs performance tweaking.  Greatly depends on the hardware.
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
