package utils

import (
	"encoding/json"
	"net/http"
	"strings"
)

// SanitizeLogInput menggantikan karakter newline dan carriage return untuk mencegah log injection
func SanitizeLogInput(input string) string {
	safe := strings.ReplaceAll(input, "\n", "_")
	safe = strings.ReplaceAll(safe, "\r", "_")
	return safe
}

// RespondWithJSON menulis response JSON ke client dengan kode status yang sesuai
func RespondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(payload)
}
