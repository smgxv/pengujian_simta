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
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// UploadICPHandler digunakan untuk mengunggah ICP
func UploadICPHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validasi ukuran file
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

	// Ambil form values
	userID := r.FormValue("user_id")
	dosenID := r.FormValue("dosen_id")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	// Ambil file dari form
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

	// Buat nama file yang aman
	safeFilename := filemanager.ValidateFileName(handler.Filename)
	filename := fmt.Sprintf("ICP_%s_%s_%s",
		userID,
		time.Now().Format("20060102150405"),
		safeFilename)

	uploadDir := "uploads/icp"

	// Validasi path upload agar tidak keluar direktori
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

	// Validasi ID numerik
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

	// Koneksi DB
	db, err := config.GetDB()
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal koneksi database: " + err.Error(),
		})
		return
	}
	defer db.Close()

	// Buat entitas ICP
	icp := &entities.ICP{
		UserID:          userIDInt,
		DosenID:         dosenIDInt,
		TopikPenelitian: topikPenelitian,
		Keterangan:      keterangan,
		FilePath:        filePath,
	}

	icpModel := models.NewICPModel(db)
	if err := icpModel.Create(icp); err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Error menyimpan ke database: " + err.Error(),
		})
		return
	}

	// Sukses
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "ICP berhasil diunggah",
		"data": map[string]interface{}{
			"file_path": filePath,
		},
	})
}

func GetICPHandler(w http.ResponseWriter, r *http.Request) {
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

	icpModel := models.NewICPModel(db)
	icps, err := icpModel.GetByUserID(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   icps,
	})
}

// DownloadFileICPHandler digunakan untuk mengunduh file ICP
func DownloadFileICPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	log.Println("🔽 [Download] Mulai proses download")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Ambil nama file dari query parameter
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Parameter 'filename' dibutuhkan", http.StatusBadRequest)
		return
	}

	// Validasi nama file: hanya izinkan karakter alfanumerik, underscore, dash, dan titik
	if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
		http.Error(w, "Nama file tidak valid", http.StatusBadRequest)
		return
	}

	// Direktori tempat file ICP disimpan
	uploadDir := "uploads/icp"
	fullPath := filepath.Join(uploadDir, filename)

	// Validasi bahwa path final masih dalam direktori yang diizinkan
	absUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	absFullPath, err := filepath.Abs(fullPath)
	if err != nil || !strings.HasPrefix(absFullPath, absUploadDir+string(os.PathSeparator)) {
		http.Error(w, "Akses file tidak sah", http.StatusForbidden)
		return
	}

	// Buka file
	file, err := os.Open(absFullPath)
	if err != nil {
		http.Error(w, "File tidak ditemukan", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Set header response
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/pdf")

	if r.Method == http.MethodHead {
		return
	}

	// Kirim isi file
	if _, err := io.Copy(w, file); err != nil {
		http.Error(w, "Gagal mengunduh file", http.StatusInternalServerError)
	}
}

func GetICPByIDHandler(w http.ResponseWriter, r *http.Request) {
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
	icpID := vars["id"]
	if icpID == "" {
		http.Error(w, "ICP ID is required", http.StatusBadRequest)
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
		query = "SELECT EXISTS(SELECT 1 FROM icp WHERE id = ? AND dosen_id = ?)"
		args = []interface{}{icpID, dosenID}
	} else {
		// For taruna, we need to check against user_id since that's what we store in ICP table
		query = "SELECT EXISTS(SELECT 1 FROM icp WHERE id = ? AND user_id = ?)"
		args = []interface{}{icpID, tarunaID}
	}

	err = db.QueryRow(query, args...).Scan(&authorized)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !authorized {
		http.Error(w, "Unauthorized: You don't have access to this ICP", http.StatusForbidden)
		return
	}

	// Get ICP details with joins to get names
	detailQuery := `
        SELECT 
            i.*,
            d.nama_lengkap as dosen_nama,
            t.nama_lengkap as nama_taruna
        FROM icp i 
        LEFT JOIN dosen d ON i.dosen_id = d.id
        LEFT JOIN taruna t ON i.user_id = t.user_id
        WHERE i.id = ?
    `

	var icp struct {
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

	err = db.QueryRow(detailQuery, icpID).Scan(
		&icp.ID,
		&icp.UserID,
		&icp.DosenID,
		&icp.TopikPenelitian,
		&icp.Keterangan,
		&icp.FilePath,
		&icp.Status,
		&icp.CreatedAt,
		&icp.UpdatedAt,
		&icp.DosenNama,
		&icp.NamaTaruna,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "ICP not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert sql.NullString to string for JSON response
	response := map[string]interface{}{
		"id":               icp.ID,
		"user_id":          icp.UserID,
		"dosen_id":         icp.DosenID,
		"topik_penelitian": icp.TopikPenelitian,
		"keterangan":       icp.Keterangan,
		"file_path":        icp.FilePath,
		"status":           icp.Status,
		"created_at":       icp.CreatedAt,
		"updated_at":       icp.UpdatedAt,
		"dosen_nama":       icp.DosenNama.String,
		"nama_taruna":      icp.NamaTaruna.String,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   response,
	})
}

func EditICPHandler(w http.ResponseWriter, r *http.Request) {
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

	icpModel := models.NewICPModel(db)
	icp, err := icpModel.GetByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update fields
	icp.DosenID, _ = strconv.Atoi(dosenID)
	icp.TopikPenelitian = topikPenelitian
	icp.Keterangan = keterangan

	// Handle file upload if new file is provided
	file, handler, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		uploadDir := "uploads/icp"
		filename := fmt.Sprintf("ICP_%d_%s_%s",
			icp.UserID,
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
		if icp.FilePath != "" {
			os.Remove(icp.FilePath)
		}

		icp.FilePath = filePath
	}

	if err := icpModel.Update(icp); err != nil {
		http.Error(w, "Error updating ICP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "ICP berhasil diupdate",
	})
}
