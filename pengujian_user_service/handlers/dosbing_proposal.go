package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"user_service/config"
	"user_service/entities"
	"user_service/models"
)

// AssignDosbingProposal digunakan untuk menyimpan data dosen pembimbing ke dalam database
func AssignDosbingProposal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
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

	var payload entities.DosbingProposal
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	model, err := models.NewDosbingModel()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if err := model.AssignPembimbing(&payload); err != nil {
		http.Error(w, "Failed to assign pembimbing", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Dosen pembimbing berhasil disimpan",
	})
}

// GetTarunaWithDosbing digunakan untuk mengambil data taruna beserta dosen pembimbing
func GetTarunaWithDosbing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
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
			d.nama_lengkap AS dosen_pembimbing
		FROM taruna t
		LEFT JOIN dosbing_proposal dp ON dp.user_id = t.user_id
		LEFT JOIN dosen d ON dp.dosen_id = d.id;
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
		var namaTaruna, jurusan, kelas, dosbing sql.NullString

		// Scan kelima kolom sesuai SELECT
		if err := rows.Scan(&tarunaID, &namaTaruna, &jurusan, &kelas, &dosbing); err != nil {
			http.Error(w, "Row scan error", http.StatusInternalServerError)
			return
		}

		result = append(result, map[string]interface{}{
			"taruna_id":        tarunaID,
			"nama_lengkap":     namaTaruna.String,
			"jurusan":          jurusan.String,
			"kelas":            kelas.String,
			"dosen_pembimbing": dosbing.String,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}
