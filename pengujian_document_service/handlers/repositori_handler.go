package handlers

import (
	"database/sql"
	"document_service/config"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"
)

// GetTugasAkhirDetailHandler digunakan untuk mengambil detail tugas akhir (untuk repositori admin)
func GetTugasAkhirDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "Revisi Laporan100 ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Ambil data dari tabel revisi_laporan100
	query := `
		SELECT 
			nama_lengkap, jurusan, kelas, tahun_akademik, 
			topik_penelitian, abstrak_id, abstrak_en, kata_kunci, link_repo,
			file_path, file_produk_path, file_bap_path
		FROM revisi_laporan100
		WHERE id = ?
	`

	var (
		namaTaruna, jurusan, kelas, tahunAkademik,
		topikPenelitian, abstrakID, abstrakEN, kataKunci, linkRepo,
		filePath, fileProdukPath, fileBapPath sql.NullString
	)

	err = db.QueryRow(query, id).Scan(
		&namaTaruna, &jurusan, &kelas, &tahunAkademik,
		&topikPenelitian, &abstrakID, &abstrakEN, &kataKunci, &linkRepo,
		&filePath, &fileProdukPath, &fileBapPath,
	)

	if err != nil {
		http.Error(w, "Data tidak ditemukan: "+err.Error(), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"nama_taruna":      nullToDash(namaTaruna),
			"jurusan":          nullToDash(jurusan),
			"kelas":            nullToDash(kelas),
			"tahun_akademik":   nullToDash(tahunAkademik),
			"topik_penelitian": nullToDash(topikPenelitian),
			"abstrak_id":       nullToDash(abstrakID),
			"abstrak_en":       nullToDash(abstrakEN),
			"kata_kunci":       nullToDash(kataKunci),
			"link_repo":        nullToDash(linkRepo),
			"file_dokumen":     nullToDash(filePath),
			"file_produk":      nullToDash(fileProdukPath),
			"file_bap":         nullToDash(fileBapPath),
		},
	}

	json.NewEncoder(w).Encode(response)
}

// Helper untuk mengganti NULL menjadi "-"
func nullToDash(s sql.NullString) string {
	if s.Valid {
		return s.String
	}
	return "-"
}

func DownloadRevisiFileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	jenis := vars["jenis"] // bisa: file, produk, bap

	if id == "" || jenis == "" {
		http.Error(w, "Missing id or jenis", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var filePath sql.NullString
	var column string

	switch jenis {
	case "file":
		column = "file_path"
	case "produk":
		column = "file_produk_path"
	case "bap":
		column = "file_bap_path"
	default:
		http.Error(w, "Jenis file tidak valid", http.StatusBadRequest)
		return
	}

	query := "SELECT " + column + " FROM revisi_laporan100 WHERE id = ? LIMIT 1"
	err = db.QueryRow(query, id).Scan(&filePath)
	if err != nil || !filePath.Valid {
		http.Error(w, "File tidak ditemukan", http.StatusNotFound)
		return
	}

	file, err := os.Open(filePath.String)
	if err != nil {
		http.Error(w, "Gagal membuka file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filePath.String))
	w.Header().Set("Content-Type", "application/pdf")
	http.ServeFile(w, r, filePath.String)
}
