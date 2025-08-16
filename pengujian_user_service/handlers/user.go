package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"user_service/entities"
	"user_service/models"
	"user_service/utils"

	"golang.org/x/crypto/bcrypt"
)

// Fungsi Get user
func UserHandler(w http.ResponseWriter, r *http.Request) {
	// CORS header (tidak perlu diubah)
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	userModel, err := models.NewUserModel()
	if err != nil {
		log.Printf("❌ Gagal koneksi DB: %v", err)
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	// Cek apakah ada parameter id
	userID := r.URL.Query().Get("id")
	if userID != "" {
		id, err := strconv.Atoi(userID)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		user, err := userModel.GetUserByID(id)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(user)
		return
	}

	// Ambil semua user
	users, err := userModel.FindAll()
	if err != nil {
		log.Printf("❌ Gagal ambil data user dari DB: %v", err)
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Berhasil ambil %d users", len(users))

	err = json.NewEncoder(w).Encode(users)
	if err != nil {
		log.Printf("❌ Gagal encode JSON: %v", err)
		http.Error(w, "Gagal encode JSON", http.StatusInternalServerError)
		return
	}
}

// Fungsi Add user
func AddUser(w http.ResponseWriter, r *http.Request) {
	// Header CORS
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	// Inisialisasi userModel
	userModel, err := models.NewUserModel()
	if err != nil {
		log.Printf("Database connection error: %v", err)
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var userData struct {
		FullName        string `json:"nama_lengkap"`
		Email           string `json:"email"`
		Username        string `json:"username"`
		Role            string `json:"role"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
		Jurusan         string `json:"jurusan"`
		Kelas           string `json:"kelas"`
		NPM             string `json:"npm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validasi password
	if userData.Password != userData.ConfirmPassword {
		http.Error(w, "Password dan Confirm Password tidak cocok!", http.StatusBadRequest)
		return
	}
	if !utils.IsValidPassword(userData.Password) {
		http.Error(w, "Password harus minimal 8 karakter, mengandung huruf besar, huruf kecil, angka, dan simbol", http.StatusBadRequest)
		return
	}

	// Kosongkan field tidak perlu untuk Admin
	if strings.ToLower(userData.Role) == "admin" {
		userData.Jurusan = ""
		userData.Kelas = ""
		userData.NPM = ""
	}

	// Cek email duplikat
	var existingUser entities.User
	userModel.Where(&existingUser, "email", userData.Email)
	if existingUser.Email != "" {
		http.Error(w, "Email sudah terdaftar!", http.StatusConflict)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Simpan user baru
	_, err = userModel.CreateUser(
		userData.FullName,
		userData.Email,
		userData.Username,
		userData.Role,
		string(hashedPassword),
		userData.Jurusan,
		userData.Kelas,
		userData.NPM,
	)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, "Gagal menambahkan user", http.StatusInternalServerError)
		return
	}

	// Kirim response sukses
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User berhasil ditambahkan",
	})
}

// fungsi edit user
func EditUser(w http.ResponseWriter, r *http.Request) {
	// CORS
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin, Accept")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Authorization header presence (opsional: validasi token sebenarnya)
	if r.Header.Get("Authorization") == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"status": "error", "message": "No token provided",
		})
		return
	}

	userModel, err := models.NewUserModel()
	if err != nil {
		log.Printf("DB error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "message": "Database connection error",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		userIDStr := r.URL.Query().Get("id")
		if userIDStr == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"status": "error", "message": "ID User tidak ditemukan",
			})
			return
		}
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"status": "error", "message": "ID User tidak valid",
			})
			return
		}

		user, err := userModel.GetUserByID(userID)
		if err != nil {
			log.Printf("GetUserByID: %v", err)
			writeJSON(w, http.StatusNotFound, map[string]any{
				"status": "error", "message": "User tidak ditemukan",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status": "success",
			"data":   user,
		})
		return

	case http.MethodPut:
		var req struct {
			UserID          int    `json:"id"`
			FullName        string `json:"nama_lengkap"`
			Email           string `json:"email"`
			Username        string `json:"username"`
			Role            string `json:"role"`
			Jurusan         string `json:"jurusan"`
			Kelas           string `json:"kelas"`
			NPM             string `json:"npm"`
			Password        string `json:"password"`
			ConfirmPassword string `json:"confirm_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Decode body: %v", err)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"status": "error", "message": "Invalid request body",
			})
			return
		}

		if req.UserID == 0 || req.FullName == "" || req.Email == "" || req.Username == "" || req.Role == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"status": "error", "message": "Semua field harus diisi",
			})
			return
		}

		var hashedPassword []byte
		if req.Password != "" {
			if req.Password != req.ConfirmPassword {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"status": "error", "message": "Password dan konfirmasi tidak cocok",
				})
				return
			}
			if !utils.IsValidPassword(req.Password) {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"status":  "error",
					"message": "Password harus minimal 8 karakter, mengandung huruf besar, huruf kecil, angka, dan simbol",
				})
				return
			}
			var err error
			hashedPassword, err = bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("Hash pwd: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"status": "error", "message": "Gagal memproses password",
				})
				return
			}
		}

		// Cek email unik
		var existing entities.User
		if err := userModel.Where(&existing, "email", req.Email); err == nil &&
			existing.ID != 0 && existing.ID != req.UserID {
			writeJSON(w, http.StatusConflict, map[string]any{
				"status": "error", "message": "Email sudah digunakan",
			})
			return
		}

		// Parse NPM (opsional)
		var npm *int
		if strings.TrimSpace(req.NPM) != "" {
			n, err := strconv.Atoi(req.NPM)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"status": "error", "message": "NPM harus berupa angka",
				})
				return
			}
			npm = &n
		}

		if err := userModel.UpdateUser(
			req.UserID, req.FullName, req.Email, req.Username,
			req.Role, req.Jurusan, req.Kelas, npm, hashedPassword,
		); err != nil {
			log.Printf("UpdateUser: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"status": "error", "message": "Gagal mengupdate user",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status": "success", "message": "User berhasil diupdate",
		})
		return

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"status": "error", "message": "Method not allowed",
		})
	}
}

// helper.go (atau di file yang sama)
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// Fungsi Get user detail
func GetUserDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "Metode tidak diizinkan",
		})
		return
	}

	userID := r.URL.Query().Get("id")
	if userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "ID User tidak ditemukan",
		})
		return
	}

	id, err := strconv.Atoi(userID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "ID User tidak valid",
		})
		return
	}

	userModel, err := models.NewUserModel()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "Gagal menghubungkan ke database",
		})
		return
	}

	user, err := userModel.GetUserByID(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "User tidak ditemukan",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// Fungsi Delete user
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Header CORS
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "Metode tidak diizinkan",
		})
		return
	}

	// Ambil ID user dari parameter URL
	userID := r.URL.Query().Get("id")
	if userID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "ID User tidak ditemukan",
		})
		return
	}

	// Konversi userID string ke int
	id, err := strconv.Atoi(userID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "ID User tidak valid",
		})
		return
	}

	// Inisialisasi user model
	userModel, err := models.NewUserModel()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "Gagal menghubungkan ke database",
		})
		return
	}

	// Cek apakah user ada di database
	user, err := userModel.GetUserByID(id)
	if err != nil || user == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "User tidak ditemukan",
		})
		return
	}

	// Hapus user dari database
	err = userModel.DeleteUser(id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  false,
			"message": "Gagal menghapus user: " + err.Error(),
		})
		return
	}

	// Kirim response sukses
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  true,
		"message": "User berhasil dihapus",
	})
}
