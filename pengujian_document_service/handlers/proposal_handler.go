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

// UploadProposalHandler digunakan untuk mengunggah proposal
func UploadProposalHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Cek ukuran file
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
			"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
		})
		return
	}

	// Ambil data form
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

	userIDInt, err := strconv.Atoi(userID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "User ID tidak valid",
		})
		return
	}

	dosenIDInt, err := strconv.Atoi(dosenID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Dosen ID tidak valid",
		})
		return
	}

	// Ambil file
	file, handler, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal mengambil file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// Validasi tipe file
	if err := filemanager.ValidateFileType(file, handler.Filename); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	file.Seek(0, 0)

	// Buat nama file aman
	safeFilename := filemanager.ValidateFileName(handler.Filename)
	filename := fmt.Sprintf("PROPOSAL_%d_%s_%s",
		userIDInt,
		time.Now().Format("20060102150405"),
		safeFilename)

	uploadDir := "uploads/proposal"

	// Validasi path akhir agar tetap di dalam folder uploadDir
	absUploadDir, _ := filepath.Abs(uploadDir)
	absFilePath, _ := filepath.Abs(filepath.Join(uploadDir, filename))
	if !strings.HasPrefix(absFilePath, absUploadDir) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "File path tidak valid",
		})
		return
	}

	// Simpan file
	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, filename)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	// Simpan ke database
	db, err := config.GetDB()
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal koneksi ke database: " + err.Error(),
		})
		return
	}
	defer db.Close()

	proposal := &entities.Proposal{
		UserID:          userIDInt,
		DosenID:         dosenIDInt,
		TopikPenelitian: topikPenelitian,
		Keterangan:      keterangan,
		FilePath:        filePath,
	}

	proposalModel := models.NewProposalModel(db)
	if err := proposalModel.Create(proposal); err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan ke database: " + err.Error(),
		})
		return
	}

	// Sukses
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Proposal berhasil diunggah",
		"data": map[string]interface{}{
			"file_path": filePath,
		},
	})
}

// GetProposalHandler digunakan untuk mengambil proposal berdasarkan user_id
func GetProposalHandler(w http.ResponseWriter, r *http.Request) {
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

	proposalModel := models.NewProposalModel(db)
	proposals, err := proposalModel.GetByUserID(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   proposals,
	})
}

// DownloadFileProposalHandler digunakan untuk mengunduh file proposal
func DownloadFileProposalHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori file laporan 70
	baseDir := "uploads/proposal"

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

func GetProposalByIDHandler(w http.ResponseWriter, r *http.Request) {
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
	proposalID := vars["id"]
	if proposalID == "" {
		http.Error(w, "Proposal ID is required", http.StatusBadRequest)
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
		query = "SELECT EXISTS(SELECT 1 FROM proposal WHERE id = ? AND dosen_id = ?)"
		args = []interface{}{proposalID, dosenID}
	} else {
		// For taruna, we need to check against user_id since that's what we store in ICP table
		query = "SELECT EXISTS(SELECT 1 FROM proposal WHERE id = ? AND user_id = ?)"
		args = []interface{}{proposalID, tarunaID}
	}

	err = db.QueryRow(query, args...).Scan(&authorized)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !authorized {
		http.Error(w, "Unauthorized: You don't have access to this Proposal", http.StatusForbidden)
		return
	}

	// Get ICP details with joins to get names
	detailQuery := `
        SELECT 
            i.*,
            d.nama_lengkap as dosen_nama,
            t.nama_lengkap as nama_taruna
        FROM proposal i 
        LEFT JOIN dosen d ON i.dosen_id = d.id
        LEFT JOIN taruna t ON i.user_id = t.user_id
        WHERE i.id = ?
    `

	var proposal struct {
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

	err = db.QueryRow(detailQuery, proposalID).Scan(
		&proposal.ID,
		&proposal.UserID,
		&proposal.DosenID,
		&proposal.TopikPenelitian,
		&proposal.Keterangan,
		&proposal.FilePath,
		&proposal.Status,
		&proposal.CreatedAt,
		&proposal.UpdatedAt,
		&proposal.DosenNama,
		&proposal.NamaTaruna,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Proposal not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert sql.NullString to string for JSON response
	response := map[string]interface{}{
		"id":               proposal.ID,
		"user_id":          proposal.UserID,
		"dosen_id":         proposal.DosenID,
		"topik_penelitian": proposal.TopikPenelitian,
		"keterangan":       proposal.Keterangan,
		"file_path":        proposal.FilePath,
		"status":           proposal.Status,
		"created_at":       proposal.CreatedAt,
		"updated_at":       proposal.UpdatedAt,
		"dosen_nama":       proposal.DosenNama.String,
		"nama_taruna":      proposal.NamaTaruna.String,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   response,
	})
}

// EditProposalHandler digunakan untuk mengedit proposal
func EditProposalHandler(w http.ResponseWriter, r *http.Request) {
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

	proposalModel := models.NewProposalModel(db)
	proposal, err := proposalModel.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update fields
	proposal.DosenID, _ = strconv.Atoi(dosenID)
	proposal.TopikPenelitian = topikPenelitian
	proposal.Keterangan = keterangan

	// Handle file upload if new file is provided
	file, handler, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		uploadDir := "uploads/proposal"
		filename := fmt.Sprintf("Proposal_%d_%s_%s",
			proposal.UserID,
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
		if proposal.FilePath != "" {
			os.Remove(proposal.FilePath)
		}

		proposal.FilePath = filePath
	}

	if err := proposalModel.Update(proposal); err != nil {
		http.Error(w, "Error updating Proposal: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Proposal berhasil diupdate",
	})
}
