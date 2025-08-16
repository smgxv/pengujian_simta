package utils

import (
	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte("secret")

func VerifyJWT(tokenStr string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
