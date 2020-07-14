package hashing

import (
	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	cost int
}

func NewBcryptHashComparer(cost int) HashComparer {
	return bcryptHasher{
		cost: cost,
	}
}

// Hash generates a hashed password using bcrypt.
func (h bcryptHasher) Hash(password string) (string, error) {
	generated, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	return string(generated), err
}

// Compare checks that a bcrypt generated password matches the password hash.
func (h bcryptHasher) Compare(password, passwordHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return false
	}
	return true
}
