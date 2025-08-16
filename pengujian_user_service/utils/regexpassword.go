package utils

import "regexp"

func IsValidPassword(password string) bool {
	// Minimal 8 karakter, 1 huruf besar, 1 huruf kecil, 1 angka, dan 1 simbol
	var (
		uppercase = regexp.MustCompile(`[A-Z]`)
		lowercase = regexp.MustCompile(`[a-z]`)
		number    = regexp.MustCompile(`[0-9]`)
		special   = regexp.MustCompile(`[\W_]`)
	)

	return len(password) >= 8 &&
		uppercase.MatchString(password) &&
		lowercase.MatchString(password) &&
		number.MatchString(password) &&
		special.MatchString(password)
}
