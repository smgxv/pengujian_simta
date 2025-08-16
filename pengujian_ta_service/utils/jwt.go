package utils

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("secret")

// Struktur klaim token
type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

// Fungsi untuk generate token JWT dengan role
func GenerateJWT(email, role string) (string, error) {
	// Standardize role to lowercase
	role = strings.ToLower(role)

	claims := &Claims{
		Email: email,
		Role:  role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Fungsi untuk parse dan verifikasi token JWT
func ParseJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("token tidak valid")
	}

	return claims, nil
}
