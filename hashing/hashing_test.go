package hashing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHasher(t *testing.T) {
	authOpts := make(map[string]string)

	hasher := NewHasher(authOpts, "")

	_, ok := hasher.(pbkdf2Hasher)
	assert.True(t, ok)

	authOpts = make(map[string]string)
	authOpts["hasher"] = Pbkdf2Opt
	hasher = NewHasher(authOpts, "")

	pHasher, ok := hasher.(pbkdf2Hasher)

	assert.True(t, ok)
	assert.Equal(t, defaultPBKDF2Algorithm, pHasher.algorithm)
	assert.Equal(t, defaultPBKDF2KeyLen, pHasher.keyLen)
	assert.Equal(t, defaultPBKDF2Iterations, pHasher.iterations)
	assert.Equal(t, defaultPBKDF2SaltSize, pHasher.saltSize)
	assert.Equal(t, Base64, pHasher.saltEncoding)

	// Check that options are set correctly.
	authOpts = make(map[string]string)
	authOpts = map[string]string{
		"hasher":               Pbkdf2Opt,
		"hasher_algorithm":     SHA256,
		"hasher_keylen":        "24",
		"hasher_iterations":    "100",
		"hasher_salt_size":     "30",
		"hasher_salt_encoding": UTF8,
	}
	hasher = NewHasher(authOpts, "")

	pHasher, ok = hasher.(pbkdf2Hasher)
	assert.True(t, ok)
	assert.Equal(t, SHA256, pHasher.algorithm)
	assert.Equal(t, 24, pHasher.keyLen)
	assert.Equal(t, 100, pHasher.iterations)
	assert.Equal(t, 30, pHasher.saltSize)
	assert.Equal(t, UTF8, pHasher.saltEncoding)

	authOpts = make(map[string]string)
	authOpts["hasher"] = Argon2IDOpt
	hasher = NewHasher(authOpts, "")

	aHasher, ok := hasher.(argon2IDHasher)

	assert.True(t, ok)
	assert.Equal(t, defaultArgon2IDIterations, aHasher.iterations)
	assert.Equal(t, defaultArgon2IDKeyLen, aHasher.keyLen)
	assert.Equal(t, defaultArgon2IDMemory, aHasher.memory)
	assert.Equal(t, defaultArgon2IDParallelism, aHasher.parallelism)
	assert.Equal(t, defaultArgon2IDSaltSize, aHasher.saltSize)

	authOpts = make(map[string]string)
	authOpts = map[string]string{
		"hasher":             Argon2IDOpt,
		"hasher_iterations":  "100",
		"hasher_keylen":      "24",
		"hasher_memory":      "1024",
		"hasher_parallelism": "4",
		"hasher_salt_size":   "24",
	}
	hasher = NewHasher(authOpts, "")

	aHasher, ok = hasher.(argon2IDHasher)

	assert.True(t, ok)
	assert.Equal(t, 100, aHasher.iterations)
	assert.Equal(t, 24, aHasher.keyLen)
	assert.Equal(t, uint32(1024), aHasher.memory)
	assert.Equal(t, uint8(4), aHasher.parallelism)
	assert.Equal(t, 24, aHasher.saltSize)

	authOpts = make(map[string]string)
	authOpts["hasher"] = BcryptOpt
	hasher = NewHasher(authOpts, "")

	bHasher, ok := hasher.(bcryptHasher)
	assert.True(t, ok)
	assert.Equal(t, bHasher.cost, defaultBcryptCost)

	// Check that options are set correctly.
	authOpts = make(map[string]string)
	authOpts = map[string]string{
		"hasher":      BcryptOpt,
		"hasher_cost": "15",
	}
	hasher = NewHasher(authOpts, "")

	bHasher, ok = hasher.(bcryptHasher)
	assert.True(t, ok)
	assert.Equal(t, 15, bHasher.cost)
}

func TestBcrypt(t *testing.T) {

	password := "test-password"
	hasher := NewBcryptHashComparer(10)

	passwordHash, err := hasher.Hash(password)

	assert.Nil(t, err)
	assert.True(t, hasher.Compare(password, passwordHash))
	assert.False(t, hasher.Compare("other", passwordHash))
}

func TestArgon2ID(t *testing.T) {
	password := "test-password"
	hasher := NewArgon2IDHasher(defaultArgon2IDSaltSize, defaultArgon2IDIterations, defaultArgon2IDKeyLen, defaultArgon2IDMemory, defaultArgon2IDParallelism)

	passwordHash, err := hasher.Hash(password)

	assert.Nil(t, err)
	assert.True(t, hasher.Compare(password, passwordHash))
	assert.False(t, hasher.Compare("other", passwordHash))
}

func TestPBKDF2(t *testing.T) {
	password := "test-password"

	// Test base64.
	hasher := NewPBKDF2Hasher(defaultPBKDF2SaltSize, defaultPBKDF2Iterations, defaultPBKDF2Algorithm, Base64, defaultPBKDF2KeyLen)

	passwordHash, err := hasher.Hash(password)

	assert.Nil(t, err)
	assert.True(t, hasher.Compare(password, passwordHash))
	assert.False(t, hasher.Compare("other", passwordHash))

	// Test UTF8.
	hasher = NewPBKDF2Hasher(defaultPBKDF2SaltSize, defaultPBKDF2Iterations, defaultPBKDF2Algorithm, UTF8, defaultPBKDF2KeyLen)

	passwordHash, err = hasher.Hash(password)

	assert.Nil(t, err)
	assert.True(t, hasher.Compare(password, passwordHash))
	assert.False(t, hasher.Compare("other", passwordHash))
}
