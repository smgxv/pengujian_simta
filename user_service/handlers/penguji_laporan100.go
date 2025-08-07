package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"user_service/config"
	"user_service/entities"
	"user_service/models"
)

// AssignPengujiLaporan100 digunakan untuk menyimpan data penguji ke dalam database
func AssignPengujiLaporan100(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://securesimta.my.id")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload entities.PengujiLaporan100
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	model, err := models.NewPengujiLaporan100Model()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if err := model.AssignPengujiLaporan100(&payload); err != nil {
		http.Error(w, "Failed to assign penguji: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Penguji berhasil disimpan",
	})
}

func GetTarunaWithPengujiLaporan100(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://securesimta.my.id")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
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
	defer db.Close()

	query := `
		SELECT 
			t.id AS taruna_id,
			t.nama_lengkap AS nama_taruna,
			t.jurusan,
			t.kelas,
			dk.nama_lengkap AS ketua_penguji,
			dp1.nama_lengkap AS penguji_1,
			dp2.nama_lengkap AS penguji_2,
			CASE 
				WHEN EXISTS (
					SELECT 1 FROM final_laporan100 f WHERE f.user_id = t.user_id
				) THEN 1 ELSE 0
			END AS sudah_kumpul
		FROM taruna t
		LEFT JOIN penguji_laporan100 pp ON pp.user_id = t.user_id
		LEFT JOIN dosen dk ON pp.ketua_penguji_id = dk.id
		LEFT JOIN dosen dp1 ON pp.penguji_1_id = dp1.id
		LEFT JOIN dosen dp2 ON pp.penguji_2_id = dp2.id
		ORDER BY t.nama_lengkap ASC;
	`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Query execution error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var tarunaID int
		var namaTaruna, jurusan, kelas sql.NullString
		var ketua, penguji1, penguji2 sql.NullString
		var sudahKumpul int

		if err := rows.Scan(&tarunaID, &namaTaruna, &jurusan, &kelas, &ketua, &penguji1, &penguji2, &sudahKumpul); err != nil {
			http.Error(w, "Row scan error", http.StatusInternalServerError)
			return
		}

		result = append(result, map[string]interface{}{
			"taruna_id":          tarunaID,
			"nama_lengkap":       namaTaruna.String,
			"jurusan":            jurusan.String,
			"kelas":              kelas.String,
			"ketua_penguji":      ketua.String,
			"penguji_1":          penguji1.String,
			"penguji_2":          penguji2.String,
			"status_pengumpulan": sudahKumpul == 1,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}

// GetFinalLaporan100ByTarunaIDHandler digunakan untuk mengambil data final laporan100 berdasarkan taruna_id
func GetFinalLaporan100ByTarunaIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://securesimta.my.id")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	tarunaID := r.URL.Query().Get("taruna_id")
	if tarunaID == "" {
		http.Error(w, "taruna_id is required", http.StatusBadRequest)
		return
	}

	db, err := config.ConnectDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Step 1: Get user_id from taruna.id
	var userID int
	err = db.QueryRow("SELECT user_id FROM taruna WHERE id = ?", tarunaID).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "not_found",
				"message": "Taruna tidak ditemukan",
			})
			return
		}
		http.Error(w, "Error querying taruna: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 2: Get final_laporan100 by user_id
	query := `SELECT id, topik_penelitian FROM final_laporan100 WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`

	var laporan100ID int
	var topik string

	err = db.QueryRow(query, userID).Scan(&laporan100ID, &topik)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "not_found",
				"message": "Taruna ini belum mengumpulkan laporan100",
			})
			return
		}
		http.Error(w, "Error querying final_laporan100: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Success response
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"id":               laporan100ID,
			"user_id":          userID,
			"topik_penelitian": topik,
		},
	})
}
