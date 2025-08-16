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
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Handler untuk mengambil ICP berdasarkan dosen_id
func GetICPByDosenIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	dosenID := r.URL.Query().Get("dosen_id")
	if dosenID == "" {
		http.Error(w, "Dosen ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	icpModel := models.NewICPModel(db)
	icps, err := icpModel.GetByDosenID(dosenID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   icps,
	})
}

// Handler untuk mengubah status ICP
func UpdateICPStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	status := r.URL.Query().Get("status")
	if id == "" || status == "" {
		http.Error(w, "ID dan status diperlukan", http.StatusBadRequest)
		return
	}

	// Validasi status hanya boleh "approved", "rejected", atau "on review"
	if status != "approved" && status != "rejected" && status != "on review" {
		http.Error(w, "Status tidak valid", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec("UPDATE icp SET status = ? WHERE id = ?", status, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	msg := "ICP berhasil diupdate"
	if status == "approved" {
		msg = "ICP berhasil di-approve"
	} else if status == "rejected" {
		msg = "ICP berhasil di-reject"
	} else if status == "on review" {
		msg = "ICP berhasil diubah ke status review"
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": msg,
	})
}

// Handler untuk mengambil daftar review ICP dari table review_icp
func GetReviewICPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	dosenID := r.URL.Query().Get("dosen_id")
	tarunaID := r.URL.Query().Get("taruna_id")

	if dosenID == "" && tarunaID == "" {
		http.Error(w, "Either dosen_id or taruna_id is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	reviewModel := models.NewReviewICPModel(db)

	var reviews []entities.ReviewICP
	if dosenID != "" {
		reviews, err = reviewModel.GetByDosenID(dosenID)
	} else {
		reviews, err = reviewModel.GetByTarunaID(tarunaID)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   reviews,
	})
}

// Handler untuk upload review ICP oleh dosen ke table review_icp_dosen
func UploadDosenReviewICPHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Cek Content-Length
	if r.ContentLength > filemanager.MaxFileSize {
		utils.RespondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status":  "error",
			"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
		})
		return
	}

	err := r.ParseMultipartForm(filemanager.MaxFileSize)
	if err != nil {
		utils.RespondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status":  "error",
			"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
		})
		return
	}

	dosenID := r.FormValue("dosen_id")
	tarunaID := r.FormValue("taruna_id")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	// Logging aman (gunakan sanitasi)
	log.Println("=== DATA DITERIMA FRONTEND ===")
	log.Println("dosen_id:", utils.SanitizeLogInput(dosenID))
	log.Println("taruna_id:", utils.SanitizeLogInput(tarunaID))
	log.Println("topik_penelitian:", utils.SanitizeLogInput(topikPenelitian))
	log.Println("keterangan:", utils.SanitizeLogInput(keterangan))

	if dosenID == "" || tarunaID == "" || topikPenelitian == "" {
		utils.RespondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status":  "error",
			"message": "Missing required fields",
		})
		return
	}

	db, err := config.GetDB()
	if err != nil {
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": "Database error: " + err.Error(),
		})
		return
	}
	defer db.Close()

	var userID int
	err = db.QueryRow("SELECT user_id FROM taruna WHERE id = ?", tarunaID).Scan(&userID)
	if err != nil {
		utils.RespondWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"status":  "error",
			"message": "Taruna tidak ditemukan berdasarkan taruna_id",
		})
		return
	}

	log.Println("user_id hasil lookup:", userID)

	var icpID int
	err = db.QueryRow(`
		SELECT id 
		FROM icp 
		WHERE user_id = ? AND topik_penelitian = ?`,
		userID, topikPenelitian).Scan(&icpID)
	if err != nil {
		utils.RespondWithJSON(w, http.StatusNotFound, map[string]interface{}{
			"status":  "error",
			"message": "ICP tidak ditemukan: " + err.Error(),
		})
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		utils.RespondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status":  "error",
			"message": "Gagal mengambil file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	if err := filemanager.ValidateFileType(file, handler.Filename); err != nil {
		utils.RespondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	file.Seek(0, 0)

	safeFilename := filemanager.ValidateFileName(handler.Filename)
	filename := fmt.Sprintf("REVIEW_ICP_DOSEN_%s_%s_%s",
		utils.SanitizeLogInput(dosenID),
		time.Now().Format("20060102150405"),
		safeFilename)
	uploadDir := "uploads/reviewicp/dosen"

	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, filename)
	if err != nil {
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		os.Remove(filePath)
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": "Gagal memulai transaksi: " + err.Error(),
		})
		return
	}

	_, err = tx.Exec("UPDATE icp SET status = ? WHERE id = ?", "on review", icpID)
	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": "Gagal update status ICP: " + err.Error(),
		})
		return
	}

	var cycleNumber int
	err = tx.QueryRow(`
		SELECT COALESCE(MAX(cycle_number), 0) + 1 
		FROM review_icp_dosen 
		WHERE icp_id = ?`, icpID).Scan(&cycleNumber)
	if err != nil {
		cycleNumber = 1
	}

	dosenIDInt, _ := strconv.Atoi(dosenID)
	tarunaIDInt, _ := strconv.Atoi(tarunaID)

	_, err = tx.Exec(`
		INSERT INTO review_icp_dosen (
			icp_id, taruna_id, dosen_id, cycle_number,
			topik_penelitian, file_path, keterangan,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
		icpID, tarunaIDInt, dosenIDInt, cycleNumber,
		topikPenelitian, filePath, keterangan,
	)

	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan review ICP: " + err.Error(),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		os.Remove(filePath)
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": "Gagal commit transaksi: " + err.Error(),
		})
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Review ICP dosen berhasil diunggah dan status diperbarui",
		"data": map[string]interface{}{
			"file_path": filePath,
		},
	})
}

// DownloadFileReviewDosenICPHandler digunakan untuk mengunduh file review ICP oleh dosen
func DownloadFileReviewDosenICPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori file review dosen
	baseDir := "uploads/reviewicp/dosen"

	// Ambil path dari query
	rawPath := r.URL.Query().Get("path")
	if rawPath == "" {
		http.Error(w, "File path is required", http.StatusBadRequest)
		return
	}
	fileName := filepath.Base(rawPath) // Hindari traversal path

	// Gabungkan path lengkap
	joinedPath := filepath.Join(baseDir, fileName)
	absPath, err := filepath.Abs(joinedPath)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	// Validasi direktori target
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

	// Salin isi file ke response
	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Error downloading file", http.StatusInternalServerError)
		return
	}
}

// Handler untuk mengambil daftar review ICP dosen dari table review_icp_dosen
func GetReviewICPDosenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	dosenID := r.URL.Query().Get("dosen_id")
	tarunaID := r.URL.Query().Get("taruna_id")

	if dosenID == "" && tarunaID == "" {
		http.Error(w, "Either dosen_id or taruna_id is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	reviewModel := models.NewReviewICPDosenModel(db)

	var reviews []entities.ReviewICP
	if dosenID != "" {
		reviews, err = reviewModel.GetByDosenID(dosenID)
	} else {
		reviews, err = reviewModel.GetByTarunaID(tarunaID)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   reviews,
	})
}

func UploadTarunaRevisiICPHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Check Content-Length
	if r.ContentLength > filemanager.MaxFileSize {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
		})
		return
	}

	err := r.ParseMultipartForm(filemanager.MaxFileSize)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
		})
		return
	}

	dosenID := r.FormValue("dosen_id")
	userID := r.FormValue("taruna_id")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	if dosenID == "" || userID == "" || topikPenelitian == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Missing required fields",
		})
		return
	}

	// Get ICP ID based on user_id and topik_penelitian
	db, err := config.GetDB()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Database error: " + err.Error(),
		})
		return
	}
	defer db.Close()

	var tarunaID int
	err = db.QueryRow("SELECT id FROM taruna WHERE user_id = ?", userID).Scan(&tarunaID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Taruna not found: " + err.Error(),
		})
		return
	}

	var icpID int
	err = db.QueryRow("SELECT id FROM icp WHERE user_id = ? AND topik_penelitian = ?", userID, topikPenelitian).Scan(&icpID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "ICP not found for the given taruna and topic",
		})
		return
	}

	// Get file
	file, handler, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Error retrieving file: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// Validate file type
	if err := filemanager.ValidateFileType(file, handler.Filename); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	file.Seek(0, 0) // Reset file pointer

	// Sanitize and build filename
	safeFilename := filemanager.ValidateFileName(handler.Filename)
	filename := fmt.Sprintf("REVISI_ICP_TARUNA_%s_%s_%s",
		dosenID,
		time.Now().Format("20060102150405"),
		safeFilename)
	uploadDir := "uploads/reviewicp/taruna"

	// Save file securely
	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, filename)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Failed to start transaction: " + err.Error(),
		})
		return
	}

	_, err = tx.Exec("UPDATE icp SET status = ? WHERE id = ?", "on review", icpID)
	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Failed to update ICP status: " + err.Error(),
		})
		return
	}

	var cycleNumber int = 1
	err = tx.QueryRow(`SELECT COALESCE(MAX(cycle_number), 0) + 1 FROM review_icp_taruna WHERE icp_id = ?`, icpID).Scan(&cycleNumber)
	if err != nil {
		cycleNumber = 1
	}

	dosenIDInt, _ := strconv.Atoi(dosenID)
	_, err = tx.Exec(`
		INSERT INTO review_icp_taruna (
			icp_id, taruna_id, dosen_id, cycle_number,
			topik_penelitian, file_path, keterangan,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
		icpID, tarunaID, dosenIDInt, cycleNumber,
		topikPenelitian, filePath, keterangan,
	)
	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Error saving to database: " + err.Error(),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Failed to commit transaction: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Revisi ICP taruna berhasil diunggah dan status diperbarui",
		"data": map[string]interface{}{
			"file_path": filePath,
		},
	})
}

// DownloadFileRevisiTarunaICPHandler digunakan untuk mengunduh file revisi ICP oleh taruna
func DownloadFileRevisiTarunaICPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori file revisi taruna
	baseDir := "uploads/reviewicp/taruna"

	// Ambil nama file dari query
	rawPath := r.URL.Query().Get("path")
	if rawPath == "" {
		http.Error(w, "File path is required", http.StatusBadRequest)
		return
	}
	fileName := filepath.Base(rawPath) // Amankan dari path traversal

	// Gabungkan path lengkap
	joinedPath := filepath.Join(baseDir, fileName)
	absPath, err := filepath.Abs(joinedPath)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	// Validasi path tetap dalam baseDir
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

	// Salin isi file ke response
	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Error downloading file", http.StatusInternalServerError)
		return
	}
}

// Handler untuk mengambil daftar revisi ICP taruna dari table review_icp_taruna
func GetRevisiICPTarunaHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	userID := r.URL.Query().Get("taruna_id") // We receive user_id as taruna_id from frontend
	dosenID := r.URL.Query().Get("dosen_id")
	icpID := r.URL.Query().Get("icp_id")

	if userID == "" && dosenID == "" {
		http.Error(w, "Either taruna_id or dosen_id is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Base query with joins to get taruna and dosen names
	query := `
		SELECT 
			rit.id,
			rit.icp_id,
			rit.taruna_id,
			rit.dosen_id,
			rit.topik_penelitian,
			rit.file_path,
			rit.keterangan,
			rit.cycle_number,
			rit.created_at,
			rit.updated_at,
			t.nama_lengkap as taruna_nama,
			t.user_id as user_id,
			d.nama_lengkap as dosen_nama
		FROM review_icp_taruna rit
		LEFT JOIN taruna t ON rit.taruna_id = t.id
		LEFT JOIN dosen d ON rit.dosen_id = d.id
		WHERE 1=1
	`
	var args []interface{}

	if userID != "" {
		query += " AND t.user_id = ?"
		args = append(args, userID)
	}

	if dosenID != "" {
		query += " AND rit.dosen_id = ?"
		args = append(args, dosenID)
	}

	if icpID != "" {
		query += " AND rit.icp_id = ?"
		args = append(args, icpID)
	}

	query += " ORDER BY rit.cycle_number DESC, rit.created_at DESC"

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var revisions []map[string]interface{}
	for rows.Next() {
		var revision struct {
			ID              int
			ICPID           int
			TarunaID        int
			DosenID         int
			TopikPenelitian string
			FilePath        string
			Keterangan      string
			CycleNumber     int
			CreatedAt       string
			UpdatedAt       string
			TarunaNama      sql.NullString
			UserID          sql.NullInt64
			DosenNama       sql.NullString
		}

		err := rows.Scan(
			&revision.ID,
			&revision.ICPID,
			&revision.TarunaID,
			&revision.DosenID,
			&revision.TopikPenelitian,
			&revision.FilePath,
			&revision.Keterangan,
			&revision.CycleNumber,
			&revision.CreatedAt,
			&revision.UpdatedAt,
			&revision.TarunaNama,
			&revision.UserID,
			&revision.DosenNama,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		revisions = append(revisions, map[string]interface{}{
			"id":               revision.ID,
			"icp_id":           revision.ICPID,
			"taruna_id":        revision.TarunaID,
			"dosen_id":         revision.DosenID,
			"topik_penelitian": revision.TopikPenelitian,
			"file_path":        revision.FilePath,
			"keterangan":       revision.Keterangan,
			"cycle_number":     revision.CycleNumber,
			"created_at":       revision.CreatedAt,
			"updated_at":       revision.UpdatedAt,
			"taruna_nama":      revision.TarunaNama.String,
			"user_id":          revision.UserID.Int64,
			"dosen_nama":       revision.DosenNama.String,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   revisions,
	})
}

// Handler untuk mengambil detail review ICP dosen berdasarkan ID
func GetReviewICPDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	// Get review ID from query parameter
	reviewID := r.URL.Query().Get("id")
	if reviewID == "" {
		http.Error(w, "Review ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := `
		SELECT 
			r.id, r.icp_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna, d.nama_lengkap as dosen_nama
		FROM review_icp_dosen r
		LEFT JOIN taruna t ON r.taruna_id = t.id
		LEFT JOIN dosen d ON r.dosen_id = d.id
		WHERE r.id = ?
	`

	var review entities.ReviewICP
	var namaTaruna, dosenNama sql.NullString
	err = db.QueryRow(query, reviewID).Scan(
		&review.ID,
		&review.ICPID,
		&review.TarunaID,
		&review.DosenID,
		&review.CycleNumber,
		&review.TopikPenelitian,
		&review.FilePath,
		&review.Keterangan,
		&review.CreatedAt,
		&review.UpdatedAt,
		&namaTaruna,
		&dosenNama,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Review not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if namaTaruna.Valid {
		review.NamaTaruna = namaTaruna.String
	}
	if dosenNama.Valid {
		review.DosenNama = dosenNama.String
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   review,
	})
}

// Handler untuk mengambil detail review ICP dosen berdasarkan ID
func GetReviewICPDosenDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	// Get review ID from query parameter
	reviewID := r.URL.Query().Get("id")
	if reviewID == "" {
		http.Error(w, "Review ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := `
		SELECT 
			r.id, r.icp_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna, d.nama_lengkap as nama_dosen,
			i.status as icp_status
		FROM review_icp_dosen r
		LEFT JOIN taruna t ON r.taruna_id = t.id
		LEFT JOIN dosen d ON r.dosen_id = d.id
		LEFT JOIN icp i ON r.icp_id = i.id
		WHERE r.id = ?
	`

	var review struct {
		ID              int            `json:"id"`
		ICPID           int            `json:"icp_id"`
		TarunaID        int            `json:"taruna_id"`
		DosenID         int            `json:"dosen_id"`
		CycleNumber     int            `json:"cycle_number"`
		TopikPenelitian string         `json:"topik_penelitian"`
		FilePath        string         `json:"file_path"`
		Keterangan      string         `json:"keterangan"`
		CreatedAt       string         `json:"created_at"`
		UpdatedAt       string         `json:"updated_at"`
		NamaTaruna      sql.NullString `json:"nama_taruna"`
		NamaDosen       sql.NullString `json:"nama_dosen"`
		ICPStatus       sql.NullString `json:"icp_status"`
	}

	err = db.QueryRow(query, reviewID).Scan(
		&review.ID,
		&review.ICPID,
		&review.TarunaID,
		&review.DosenID,
		&review.CycleNumber,
		&review.TopikPenelitian,
		&review.FilePath,
		&review.Keterangan,
		&review.CreatedAt,
		&review.UpdatedAt,
		&review.NamaTaruna,
		&review.NamaDosen,
		&review.ICPStatus,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Review not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert sql.NullString to string for JSON response
	response := map[string]interface{}{
		"id":               review.ID,
		"icp_id":           review.ICPID,
		"taruna_id":        review.TarunaID,
		"dosen_id":         review.DosenID,
		"cycle_number":     review.CycleNumber,
		"topik_penelitian": review.TopikPenelitian,
		"file_path":        review.FilePath,
		"keterangan":       review.Keterangan,
		"created_at":       review.CreatedAt,
		"updated_at":       review.UpdatedAt,
		"nama_taruna":      review.NamaTaruna.String,
		"nama_dosen":       review.NamaDosen.String,
		"icp_status":       review.ICPStatus.String,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   response,
	})
}
