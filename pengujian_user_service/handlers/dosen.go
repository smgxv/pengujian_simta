package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"user_service/entities"
	"user_service/models"
	"user_service/utils"

	"golang.org/x/crypto/bcrypt"
)

func GetAllDosen(w http.ResponseWriter, r *http.Request) {
	// Set header CORS
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dosenModel, err := models.NewDosenModel()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	dosens, err := dosenModel.GetAllDosen()
	if err != nil {
		http.Error(w, "Failed to fetch dosen data", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   dosens,
	})
}

// Edit user dosen
func EditUserDosen(w http.ResponseWriter, r *http.Request) {
	// Header CORS
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin, Accept")
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

	if r.Method == http.MethodGet {
		// Ambil ID user dari parameter URL
		userIDStr := r.URL.Query().Get("id")
		if userIDStr == "" {
			http.Error(w, "ID User tidak ditemukan", http.StatusBadRequest)
			return
		}

		// Konversi ID string ke int
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			http.Error(w, "ID User tidak valid", http.StatusBadRequest)
			return
		}

		// Ambil data user yang akan diedit
		user, err := userModel.GetUserByID(userID)
		if err != nil {
			http.Error(w, "User tidak ditemukan", http.StatusNotFound)
			return
		}

		// Kirim response dalam format JSON
		json.NewEncoder(w).Encode(user)

	} else if r.Method == http.MethodPut {
		// Parse request body
		var userData struct {
			UserID   int    `json:"id"`
			FullName string `json:"nama_lengkap"`
			Email    string `json:"email"`
			Username string `json:"username"`
			Role     string `json:"role"`
			Jurusan  string `json:"jurusan"`
			Password string `json:"password,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
			log.Printf("Error decoding request body: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validasi data yang diperlukan
		if userData.UserID == 0 || userData.FullName == "" || userData.Email == "" || userData.Username == "" {
			http.Error(w, "Semua field harus diisi", http.StatusBadRequest)
			return
		}

		// Cek apakah email sudah digunakan oleh user lain
		var existingUser entities.User
		err = userModel.Where(&existingUser, "email", userData.Email)
		if err == nil && existingUser.ID != userData.UserID && existingUser.Email != "" {
			http.Error(w, "Email sudah digunakan", http.StatusConflict)
			return
		}

		// Update data user
		err = userModel.UpdateUser(userData.UserID, userData.FullName, userData.Email, userData.Username, "dosen", userData.Jurusan, "", nil, nil)
		if err != nil {
			log.Printf("Failed to update user: %v", err)
			http.Error(w, "Gagal mengupdate user", http.StatusInternalServerError)
			return
		}

		// Update data dosen
		dosenModel, err := models.NewDosenModel()
		if err != nil {
			log.Printf("Database connection error: %v", err)
			http.Error(w, "Database connection error", http.StatusInternalServerError)
			return
		}

		err = dosenModel.UpdateDosen(userData.UserID, userData.FullName, userData.Jurusan)
		if err != nil {
			log.Printf("Failed to update dosen: %v", err)
			http.Error(w, "Gagal mengupdate dosen", http.StatusInternalServerError)
			return
		}

		// Jika password diisi, hash dan update password
		if userData.Password != "" {
			// Validasi kekuatan password
			if !utils.IsValidPassword(userData.Password) {
				http.Error(w, "Password harus minimal 8 karakter, mengandung huruf besar, huruf kecil, angka, dan simbol", http.StatusBadRequest)
				return
			}

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("Failed to hash password: %v", err)
				http.Error(w, "Gagal mengupdate password", http.StatusInternalServerError)
				return
			}

			err = dosenModel.UpdateDosenPassword(userData.UserID, string(hashedPassword))
			if err != nil {
				log.Printf("Failed to update password: %v", err)
				http.Error(w, "Gagal mengupdate password", http.StatusInternalServerError)
				return
			}
		}

		// Kirim response sukses
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User berhasil diupdate",
		})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
