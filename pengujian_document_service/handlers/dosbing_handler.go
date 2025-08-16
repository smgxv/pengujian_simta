package handlers

import (
	"database/sql"
	"document_service/config"
	"encoding/json"
	"net/http"
)

// GetProposalByDosenIDHandler digunakan untuk mengambil proposal berdasarkan dosen_id
func GetDosbingByUserID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := `SELECT d.id, d.nama_lengkap FROM dosbing_proposal dp JOIN dosen d ON dp.dosen_id = d.id WHERE dp.user_id = ? LIMIT 1`
	row := db.QueryRow(query, userID)

	var dosenID int
	var namaLengkap string
	err = row.Scan(&dosenID, &namaLengkap)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "empty",
				"message": "Belum memiliki dosen pembimbing",
			})
			return
		}
		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"dosen_id": dosenID,
			"nama":     namaLengkap,
		},
	})
}
