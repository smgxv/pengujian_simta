package handlers

import (
	"database/sql"
	"document_service/config"
	"document_service/entities"
	"document_service/models"
	"document_service/utils/filemanager"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// UploadLaporan100Handler digunakan untuk mengunggah laporan 100%
func UploadLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.ContentLength > filemanager.MaxFileSize {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
		})
		return
	}

	if err := r.ParseMultipartForm(filemanager.MaxFileSize); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "File terlalu besar atau format tidak sesuai: " + err.Error(),
		})
		return
	}

	userID := r.FormValue("user_id")
	dosenID := r.FormValue("dosen_id")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	if dosenID == "" || dosenID == "0" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Dosen pembimbing belum ditentukan",
		})
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal mengambil file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	if err := filemanager.ValidateFileType(file, handler.Filename); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	file.Seek(0, 0)

	safeFilename := filemanager.ValidateFileName(handler.Filename)
	filename := fmt.Sprintf("LAPORAN100_%s_%s_%s", userID, time.Now().Format("20060102150405"), safeFilename)

	uploadDir := "uploads/laporan100"
	absUploadDir, _ := filepath.Abs(uploadDir)
	absFilePath, _ := filepath.Abs(filepath.Join(uploadDir, filename))
	if !strings.HasPrefix(absFilePath, absUploadDir) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Path file tidak valid",
		})
		return
	}

	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, filename)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan file: " + err.Error(),
		})
		return
	}

	db, err := config.GetDB()
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Koneksi database gagal: " + err.Error(),
		})
		return
	}
	defer db.Close()

	userIDInt, err := strconv.Atoi(userID)
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "User ID tidak valid",
		})
		return
	}

	dosenIDInt, err := strconv.Atoi(dosenID)
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Dosen ID tidak valid",
		})
		return
	}

	laporan := &entities.Laporan100{
		UserID:          userIDInt,
		DosenID:         dosenIDInt,
		TopikPenelitian: topikPenelitian,
		Keterangan:      keterangan,
		FilePath:        filePath,
	}

	model := models.NewLaporan100Model(db)
	if err := model.Create(laporan); err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan ke database: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Laporan 100% berhasil diunggah",
		"data": map[string]interface{}{
			"file_path": filePath,
		},
	})
}

// GetLaporan100Handler digunakan untuk mengambil Laporan 100% berdasarkan user_id
func GetLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

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

	laporan100Model := models.NewLaporan100Model(db)
	laporan100s, err := laporan100Model.GetByUserID(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   laporan100s,
	})
}

// DownloadFileLaporan100Handler digunakan untuk mengunduh file laporan 100
func DownloadFileLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori file laporan 70
	baseDir := "uploads/laporan100"

	// Ambil nama file dari query
	rawPath := r.URL.Query().Get("path")
	if rawPath == "" {
		http.Error(w, "File path is required", http.StatusBadRequest)
		return
	}
	fileName := filepath.Base(rawPath) // Hanya ambil nama file-nya

	// Bangun path lengkap
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

	// Header download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/pdf")

	// Kirim isi file
	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Error downloading file", http.StatusInternalServerError)
		return
	}
}

func GetLaporan100ByIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	// Get either dosen_id or taruna_id from query parameter
	dosenID := r.URL.Query().Get("dosen_id")
	tarunaID := r.URL.Query().Get("taruna_id")

	if dosenID == "" && tarunaID == "" {
		http.Error(w, "Either dosen_id or taruna_id is required", http.StatusBadRequest)
		return
	}

	// Ambil ID dari path parameter
	vars := mux.Vars(r)
	laporan100ID := vars["id"]
	if laporan100ID == "" {
		http.Error(w, "Laporan 100% ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Check access rights
	var authorized bool
	var query string
	var args []interface{}

	if dosenID != "" {
		query = "SELECT EXISTS(SELECT 1 FROM laporan_100 WHERE id = ? AND dosen_id = ?)"
		args = []interface{}{laporan100ID, dosenID}
	} else {
		// For taruna, we need to check against user_id since that's what we store in ICP table
		query = "SELECT EXISTS(SELECT 1 FROM laporan_100 WHERE id = ? AND user_id = ?)"
		args = []interface{}{laporan100ID, tarunaID}
	}

	err = db.QueryRow(query, args...).Scan(&authorized)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !authorized {
		http.Error(w, "Unauthorized: You don't have access to this Laporan 100%", http.StatusForbidden)
		return
	}

	// Get ICP details with joins to get names
	detailQuery := `
        SELECT 
            i.*,
            d.nama_lengkap as dosen_nama,
            t.nama_lengkap as nama_taruna
        FROM laporan_100 i 
        LEFT JOIN dosen d ON i.dosen_id = d.id
        LEFT JOIN taruna t ON i.user_id = t.user_id
        WHERE i.id = ?
    `

	var laporan100 struct {
		ID              int            `json:"id"`
		UserID          int            `json:"user_id"`
		DosenID         int            `json:"dosen_id"`
		TopikPenelitian string         `json:"topik_penelitian"`
		Keterangan      string         `json:"keterangan"`
		FilePath        string         `json:"file_path"`
		Status          string         `json:"status"`
		CreatedAt       string         `json:"created_at"`
		UpdatedAt       string         `json:"updated_at"`
		DosenNama       sql.NullString `json:"dosen_nama"`
		NamaTaruna      sql.NullString `json:"nama_taruna"`
	}

	err = db.QueryRow(detailQuery, laporan100ID).Scan(
		&laporan100.ID,
		&laporan100.UserID,
		&laporan100.DosenID,
		&laporan100.TopikPenelitian,
		&laporan100.Keterangan,
		&laporan100.FilePath,
		&laporan100.Status,
		&laporan100.CreatedAt,
		&laporan100.UpdatedAt,
		&laporan100.DosenNama,
		&laporan100.NamaTaruna,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "laporan100 not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert sql.NullString to string for JSON response
	response := map[string]interface{}{
		"id":               laporan100.ID,
		"user_id":          laporan100.UserID,
		"dosen_id":         laporan100.DosenID,
		"topik_penelitian": laporan100.TopikPenelitian,
		"keterangan":       laporan100.Keterangan,
		"file_path":        laporan100.FilePath,
		"status":           laporan100.Status,
		"created_at":       laporan100.CreatedAt,
		"updated_at":       laporan100.UpdatedAt,
		"dosen_nama":       laporan100.DosenNama.String,
		"nama_taruna":      laporan100.NamaTaruna.String,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   response,
	})
}

// EditLaporan100Handler digunakan untuk mengedit proposal
func EditLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Error parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}

	id := r.FormValue("id")
	dosenID := r.FormValue("dosen_id")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	laporan100Model := models.NewLaporan100Model(db)
	laporan100, err := laporan100Model.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update fields
	laporan100.DosenID, _ = strconv.Atoi(dosenID)
	laporan100.TopikPenelitian = topikPenelitian
	laporan100.Keterangan = keterangan

	// Handle file upload if new file is provided
	file, handler, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		uploadDir := "uploads/laporan100"
		filename := fmt.Sprintf("Laporan100_%d_%s_%s",
			laporan100.UserID,
			time.Now().Format("20060102150405"),
			handler.Filename)

		filePath := filepath.Join(uploadDir, filename)

		dst, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Error creating file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "Error saving file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete old file if exists
		if laporan100.FilePath != "" {
			os.Remove(laporan100.FilePath)
		}

		laporan100.FilePath = filePath
	}

	if err := laporan100Model.Update(laporan100); err != nil {
		http.Error(w, "Error updating Laporan 70: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Laporan berhasil diupdate",
	})
}
