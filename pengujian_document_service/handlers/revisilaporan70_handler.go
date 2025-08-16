package handlers

import (
	"database/sql"
	"document_service/config"
	"document_service/entities"
	"document_service/models"
	"document_service/utils"
	"document_service/utils/filemanager"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Handler untuk mengupload final proposal
func UploadRevisiLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.ContentLength > filemanager.MaxFileSize {
		http.Error(w, "Ukuran file terlalu besar. Maksimal 15MB", http.StatusRequestEntityTooLarge)
		return
	}

	err := r.ParseMultipartForm(filemanager.MaxFileSize)
	if err != nil {
		http.Error(w, "Gagal parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}

	userID := r.FormValue("user_id")
	namaLengkap := r.FormValue("nama_lengkap")
	jurusan := r.FormValue("jurusan")
	kelas := r.FormValue("kelas")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	if userID == "" || namaLengkap == "" || topikPenelitian == "" {
		http.Error(w, "Field user_id, nama_lengkap, dan topik_penelitian wajib diisi", http.StatusBadRequest)
		return
	}

	// === Upload File Revisi Laporan 70 ===
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Gagal membaca file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	if err := filemanager.ValidateFileType(file, handler.Filename); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	file.Seek(0, 0)

	safeName := filemanager.ValidateFileName(handler.Filename)
	filename := fmt.Sprintf("FINAL_LAPORAN70_%s_%s_%s", userID, time.Now().Format("20060102150405"), safeName)

	uploadDir := "uploads/revisifinallaporan70"
	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, filename)
	if err != nil {
		http.Error(w, "Gagal menyimpan file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// === Simpan ke database ===
	db, err := config.GetDB()
	if err != nil {
		os.Remove(filePath)
		http.Error(w, "Gagal koneksi ke database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	revisiLaporan70Model := models.NewRevisiLaporan70Model(db)
	revisiLaporan70 := &entities.RevisiLaporan70{
		UserID:          utils.ParseInt(userID),
		NamaLengkap:     namaLengkap,
		Jurusan:         jurusan,
		Kelas:           kelas,
		TopikPenelitian: topikPenelitian,
		FilePath:        filePath,
		Keterangan:      keterangan,
	}

	if err := revisiLaporan70Model.Create(revisiLaporan70); err != nil {
		os.Remove(filePath)
		http.Error(w, "Gagal menyimpan ke database: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Final Laporan 70% berhasil diunggah",
		"data": map[string]interface{}{
			"id":        revisiLaporan70.ID,
			"file_path": filePath,
		},
	})
}

// DownloadFileRevisiLaporan70Handler digunakan untuk mengunduh file revisi final laporan 70 taruna
func DownloadFileRevisiLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori penyimpanan file revisi
	baseDir := "uploads/revisifinallaporan70"

	// Ambil nama file dari query
	rawPath := r.URL.Query().Get("path")
	if rawPath == "" {
		http.Error(w, "File path is required", http.StatusBadRequest)
		return
	}
	fileName := filepath.Base(rawPath) // Amankan dari traversal path

	// Gabungkan path lengkap
	joinedPath := filepath.Join(baseDir, fileName)
	absPath, err := filepath.Abs(joinedPath)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	// Pastikan masih dalam direktori yang diizinkan
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil || !strings.HasPrefix(absPath, baseAbs) {
		http.Error(w, "Unauthorized file path", http.StatusForbidden)
		return
	}

	// Buka file
	file, err := os.Open(absPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Header untuk download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/pdf")

	// Kirim isi file
	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Error downloading file", http.StatusInternalServerError)
		return
	}
}

// Handler untuk mengambil daftar final proposal berdasarkan user_id
func GetRevisiLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	revisiLaporan70Model := models.NewRevisiLaporan70Model(db)
	revisiLaporan70s, err := revisiLaporan70Model.GetByUserID(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   revisiLaporan70s,
	})
}

// Handler untuk mengambil data gabungan taruna dan final proposal
func GetAllRevisiLaporan70WithTarunaHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Query untuk mengambil data gabungan
	query := `
		SELECT 
			t.user_id as taruna_id,
			t.nama_lengkap,
			t.jurusan,
			t.kelas,
			COALESCE(f.topik_penelitian, '') as topik_penelitian,
			COALESCE(f.status, '') as status,
			COALESCE(f.id, 0) as revisi_laporan70_id
		FROM taruna t
		LEFT JOIN revisi_laporan70 f ON t.user_id = f.user_id
		ORDER BY t.nama_lengkap ASC`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TarunaLaporan70 struct {
		TarunaID          int    `json:"taruna_id"`
		NamaLengkap       string `json:"nama_lengkap"`
		Jurusan           string `json:"jurusan"`
		Kelas             string `json:"kelas"`
		TopikPenelitian   string `json:"topik_penelitian"`
		Status            string `json:"status"`
		RevisiLaporan70ID int    `json:"revisi_laporan70_id"`
	}

	var results []TarunaLaporan70
	for rows.Next() {
		var data TarunaLaporan70
		err := rows.Scan(
			&data.TarunaID,
			&data.NamaLengkap,
			&data.Jurusan,
			&data.Kelas,
			&data.TopikPenelitian,
			&data.Status,
			&data.RevisiLaporan70ID,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		results = append(results, data)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   results,
	})
}

// Handler untuk update status Final Proposal
func UpdateRevisiLaporan70StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var requestData struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := "UPDATE revisi_laporan70 SET status = ? WHERE id = ?"
	_, err = db.Exec(query, requestData.Status, requestData.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Status berhasil diupdate",
	})
}

// Handler untuk download file Final Proposal
func DownloadRevisiLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	laporan70ID := vars["id"]

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var filePath string
	query := "SELECT file_path FROM revisi_laporan70 WHERE id = ?"
	err = db.QueryRow(query, laporan70ID).Scan(&filePath)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	fileName := filepath.Base(filePath)
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/pdf")

	http.ServeFile(w, r, filePath)
}
