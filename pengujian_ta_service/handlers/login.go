package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"ta_service/entities"
	"ta_service/models"
	"ta_service/utils"
	"time"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

// Validated login input
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type LoginResponse struct {
	Email       string `json:"email"`
	ID          int64  `json:"id"`
	DosenID     int64  `json:"dosen_id"`
	Token       string `json:"token"`
	Role        string `json:"role"`
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url"`
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("=== Memulai proses login ===")

	// CORS Headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println("❌ Gagal decode JSON:", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Trim input
	req.Email = strings.TrimSpace(req.Email)
	req.Email = strings.ToLower(req.Email)
	req.Password = strings.TrimSpace(req.Password)

	// Validasi input
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		log.Println("❌ Validasi input gagal:", err)
		http.Error(w, "Email atau password tidak valid", http.StatusBadRequest)
		return
	}

	// Anti brute force (minimal delay)
	time.Sleep(1 * time.Second)

	log.Printf("Mencari user dengan email: '%s'", req.Email) // <<<<< TAMBAHKAN INI

	// Cari user
	userModel := models.NewUserModel()
	var user entities.User

	if err := userModel.Where(&user, "email", req.Email); err != nil {
		log.Println("⚠️ Email tidak ditemukan")
		json.NewEncoder(w).Encode(map[string]string{"error": "Email atau password salah"})
		return
	}

	// Bandingkan password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		log.Println("⚠️ Password salah")
		json.NewEncoder(w).Encode(map[string]string{"error": "Email atau password salah"})
		return
	}

	// Generate JWT
	token, err := utils.GenerateJWT(user.Email, user.Role)
	if err != nil {
		log.Println("❌ Gagal generate token:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	var dosenID int64 = 0
	if user.Role == "dosen" {
		dosenID, _ = userModel.GetDosenIDByUserID(user.ID)
	}

	// Kirim response (tanpa users)
	response := LoginResponse{
		Email:       user.Email,
		ID:          user.ID,
		DosenID:     dosenID,
		Token:       token,
		Role:        user.Role,
		Success:     true,
		RedirectURL: getDashboardURL(user.Role),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("❌ Gagal kirim response:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Login berhasil untuk user: %s", user.Email)
}

func getDashboardURL(role string) string {
	switch strings.ToLower(role) {
	case "taruna":
		return "/taruna/dashboard"
	case "dosen":
		return "/dosen/dashboard"
	default:
		return "/admin/dashboard"
	}
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("🔄 Memproses logout...")

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	// Handle preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		log.Println("❌ ERROR: Method tidak diizinkan:", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// List of common auth cookies
	cookies := []string{
		"token", "role", "session", "userId", "username",
		"auth", "user_session", "remember_token",
	}

	// Paths to invalidate
	paths := []string{"/", "/admin", "/taruna", "/admin/", "/taruna/"}

	// Hapus cookies
	for _, cookieName := range cookies {
		for _, path := range paths {
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    "",
				Path:     path,
				Expires:  time.Now().Add(-24 * time.Hour),
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
		}
	}

	// Beri response JSON
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"message":  "Logout berhasil",
		"redirect": "/loginusers",
	}); err != nil {
		log.Println("❌ ERROR: Gagal mengirim response logout:", err)
	}

	log.Println("✅ Logout berhasil")
}
