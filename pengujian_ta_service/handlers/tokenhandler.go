package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"ta_service/utils"

	"github.com/golang-jwt/jwt/v4"
)

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Ambil token lama dari header
	oldToken := r.Header.Get("Authorization")
	if oldToken == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}
	oldToken = strings.Replace(oldToken, "Bearer ", "", 1)

	// Validasi token lama
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(oldToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Generate token baru
	newToken, err := utils.GenerateJWT(claims.Subject, "user") // menambahkan parameter kedua "user" sebagai role
	if err != nil {
		http.Error(w, "Failed to generate new token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": newToken,
	})
}
