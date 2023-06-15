package utils

import (
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), 5)

	return string(bytes)
}

func CheckPassword(password string, hash string) bool {
	sqli := regexp.MustCompile(`[\p{C}';"]`)
	if sqli.MatchString(password) {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err == nil
}

func RegexforACC(email string, password string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	passwordRegex := regexp.MustCompile(`^(?=.*[A-Z])(?=.*[\W_])[A-Za-z\W_]{8,}$`)
	if emailRegex.MatchString(email) && passwordRegex.MatchString(password) {
		return true
	} else {
		return false
	}
}
