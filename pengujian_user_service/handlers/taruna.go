package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"user_service/config"
	"user_service/entities"
	"user_service/models"
	"user_service/utils"

	"golang.org/x/crypto/bcrypt"
)

func GetAllTaruna(w http.ResponseWriter, r *http.Request) {
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

	tarunaModel, err := models.NewTarunaModel()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	tarunas, err := tarunaModel.GetAllTaruna()
	if err != nil {
		http.Error(w, "Failed to fetch taruna data", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   tarunas,
	})
}

// Edit user taruna
func EditUserTaruna(w http.ResponseWriter, r *http.Request) {
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
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	userModel, err := models.NewUserModel()
	if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		userIDStr := r.URL.Query().Get("id")
		if userIDStr == "" {
			http.Error(w, "ID User tidak ditemukan", http.StatusBadRequest)
			return
		}
		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			http.Error(w, "ID User tidak valid", http.StatusBadRequest)
			return
		}
		user, err := userModel.GetUserByID(userID)
		if err != nil {
			http.Error(w, "User tidak ditemukan", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(user)
		return
	}

	if r.Method == http.MethodPut {
		var userData struct {
			UserID   int    `json:"id"`
			FullName string `json:"nama_lengkap"`
			Email    string `json:"email"`
			Username string `json:"username"`
			Jurusan  string `json:"jurusan"`
			Kelas    string `json:"kelas"`
			NPM      string `json:"npm"`
			Password string `json:"password,omitempty"`
			Role     string `json:"role,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
			log.Printf("Error decoding request body: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if userData.UserID == 0 || userData.FullName == "" || userData.Email == "" || userData.Username == "" {
			http.Error(w, "Semua field harus diisi", http.StatusBadRequest)
			return
		}

		var existingUser entities.User
		err = userModel.Where(&existingUser, "email", userData.Email)
		if err == nil && existingUser.ID != userData.UserID {
			http.Error(w, "Email sudah digunakan", http.StatusConflict)
			return
		}

		var npm *int
		if userData.NPM != "" {
			npmVal, err := strconv.Atoi(userData.NPM)
			if err != nil {
				http.Error(w, "NPM harus berupa angka", http.StatusBadRequest)
				return
			}
			npm = &npmVal
		}

		err = userModel.UpdateUser(
			userData.UserID,
			userData.FullName,
			userData.Email,
			userData.Username,
			"Taruna", // role ditetapkan langsung
			userData.Jurusan,
			userData.Kelas,
			npm,
			nil,
		)

		if err != nil {
			log.Printf("Gagal update user: %v", err)
			http.Error(w, "Gagal mengupdate user", http.StatusInternalServerError)
			return
		}

		if userData.Password != "" {
			if !utils.IsValidPassword(userData.Password) {
				http.Error(w, "Password harus minimal 8 karakter, mengandung huruf besar, huruf kecil, angka, dan simbol", http.StatusBadRequest)
				return
			}

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("Hash error: %v", err)
				http.Error(w, "Gagal mengupdate password", http.StatusInternalServerError)
				return
			}

			tarunaModel, err := models.NewTarunaModel()
			if err != nil {
				log.Printf("Database error: %v", err)
				http.Error(w, "Database connection error", http.StatusInternalServerError)
				return
			}

			err = tarunaModel.UpdateTarunaPassword(userData.UserID, string(hashedPassword))
			if err != nil {
				log.Printf("Update password error: %v", err)
				http.Error(w, "Gagal mengupdate password", http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User berhasil diupdate",
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Get taruna with topik
func GetTarunaWithTopik(w http.ResponseWriter, r *http.Request) {
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

	db, err := config.ConnectDB()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}

	query := `
		SELECT 
			t.id AS taruna_id,
			t.nama_lengkap,
			t.jurusan,
			t.kelas
		FROM taruna t
		JOIN users u ON t.user_id = u.id
		WHERE u.role = 'Taruna'
	`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var tarunas []map[string]interface{}
	for rows.Next() {
		var id int
		var nama, jurusan, kelas sql.NullString

		if err := rows.Scan(&id, &nama, &jurusan, &kelas); err != nil {
			http.Error(w, "Data scan error", http.StatusInternalServerError)
			return
		}

		taruna := map[string]interface{}{
			"id":           id,
			"nama_lengkap": nama.String,
			"jurusan":      jurusan.String,
			"kelas":        kelas.String,
		}
		tarunas = append(tarunas, taruna)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   tarunas,
	})
}
