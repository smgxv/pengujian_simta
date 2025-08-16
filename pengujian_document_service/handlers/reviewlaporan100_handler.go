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
)

// Handler untuk mengambil daftar ICP dari table icp
func GetLaporan100ByDosenIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	dosenID := r.URL.Query().Get("dosen_id")
	if dosenID == "" {
		http.Error(w, "Dosen ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Gagal menghubungkan ke database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	laporan100Model := models.NewLaporan100Model(db)
	laporan100s, err := laporan100Model.GetByDosenID(dosenID)
	if err != nil {
		http.Error(w, "Gagal mengambil data laporan 70%", http.StatusInternalServerError)
		return
	}

	// Pastikan data bukan nil agar aman di frontend
	if laporan100s == nil {
		laporan100s = []entities.Laporan100{}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Data laporan 70% berhasil diambil",
		"data":    laporan100s,
	})
}

// Handler untuk mengubah status ICP
func UpdateLaporan100StatusHandler(w http.ResponseWriter, r *http.Request) {
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

	_, err = db.Exec("UPDATE laporan_100 SET status = ? WHERE id = ?", status, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	msg := "Laporan 100% berhasil diupdate"
	if status == "approved" {
		msg = "Laporan 100% berhasil di-approve"
	} else if status == "rejected" {
		msg = "Laporan 100% berhasil di-reject"
	} else if status == "on review" {
		msg = "Laporan 100% berhasil diubah ke status review"
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": msg,
	})
}

// Handler untuk upload review laporan 100% oleh dosen ke table review_laporan100_dosen
func UploadDosenReviewLaporan100Handler(w http.ResponseWriter, r *http.Request) {
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
			"message": "File terlalu besar. Maksimal 15MB.",
		})
		return
	}

	err := r.ParseMultipartForm(filemanager.MaxFileSize)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal parsing form: " + err.Error(),
		})
		return
	}

	dosenID := r.FormValue("dosen_id")
	tarunaID := r.FormValue("taruna_id")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	if dosenID == "" || tarunaID == "" || topikPenelitian == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Field wajib tidak lengkap",
		})
		return
	}

	db, err := config.GetDB()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal koneksi database: " + err.Error(),
		})
		return
	}
	defer db.Close()

	// Ambil user_id berdasarkan taruna_id
	var userID int
	err = db.QueryRow("SELECT user_id FROM taruna WHERE id = ?", tarunaID).Scan(&userID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Taruna tidak ditemukan",
		})
		return
	}

	// Ambil laporan_100 ID berdasarkan user_id dan topik
	var laporan100ID int
	err = db.QueryRow(`SELECT id FROM laporan_100 WHERE user_id = ? AND topik_penelitian = ?`, userID, topikPenelitian).Scan(&laporan100ID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Laporan 100% tidak ditemukan",
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
	finalName := fmt.Sprintf("REVIEW_LAPORAN100_DOSEN_%s_%s_%s", dosenID, time.Now().Format("20060102150405"), safeFilename)
	uploadDir := "uploads/reviewlaporan100/dosen"

	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, finalName)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan file: " + err.Error(),
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal memulai transaksi: " + err.Error(),
		})
		return
	}

	// Update status laporan_100
	_, err = tx.Exec("UPDATE laporan_100 SET status = ? WHERE id = ?", "on review", laporan100ID)
	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal update status laporan_100: " + err.Error(),
		})
		return
	}

	var cycleNumber int
	err = tx.QueryRow(`
		SELECT COALESCE(MAX(cycle_number), 0) + 1 
		FROM review_laporan100_dosen 
		WHERE laporan100_id = ?`, laporan100ID).Scan(&cycleNumber)
	if err != nil {
		cycleNumber = 1
	}

	dosenIDInt, _ := strconv.Atoi(dosenID)
	tarunaIDInt, _ := strconv.Atoi(tarunaID)

	_, err = tx.Exec(`
		INSERT INTO review_laporan100_dosen (
			laporan100_id, taruna_id, dosen_id, cycle_number,
			topik_penelitian, file_path, keterangan,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
		laporan100ID, tarunaIDInt, dosenIDInt, cycleNumber,
		topikPenelitian, filePath, keterangan,
	)
	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan review: " + err.Error(),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Commit transaksi gagal: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Review laporan 100% berhasil diunggah",
		"data": map[string]interface{}{
			"file_path": filePath,
		},
	})
}

// DownloadFileReviewDosenLaporan100Handler digunakan untuk mengunduh file review laporan 100% oleh dosen
func DownloadFileReviewDosenLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori file review dosen
	baseDir := "uploads/reviewlaporan100/dosen"

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
func GetReviewLaporan100DosenHandler(w http.ResponseWriter, r *http.Request) {
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

	reviewModel := models.NewReviewLaporan100DosenModel(db)

	var reviews []entities.ReviewLaporan100
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

// Handler untuk upload revisi laporan 70% oleh taruna ke table review_laporan100_taruna
func UploadTarunaRevisiLaporan100Handler(w http.ResponseWriter, r *http.Request) {
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

	err := r.ParseMultipartForm(filemanager.MaxFileSize)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Error parsing form: " + err.Error(),
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
			"message": "Field dosen_id, taruna_id, dan topik_penelitian wajib diisi",
		})
		return
	}

	db, err := config.GetDB()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Koneksi ke database gagal: " + err.Error(),
		})
		return
	}
	defer db.Close()

	var tarunaID int
	err = db.QueryRow("SELECT id FROM taruna WHERE user_id = ?", userID).Scan(&tarunaID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Taruna tidak ditemukan: " + err.Error(),
		})
		return
	}

	var laporan100ID int
	err = db.QueryRow("SELECT id FROM laporan_100 WHERE user_id = ? AND topik_penelitian = ?", userID, topikPenelitian).Scan(&laporan100ID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Laporan 100% tidak ditemukan untuk taruna dan topik ini",
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
	finalName := fmt.Sprintf("REVISI_LAPORAN100_TARUNA_%s_%s_%s",
		userID,
		time.Now().Format("20060102150405"),
		safeFilename)

	uploadDir := "uploads/reviewlaporan100/taruna"
	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, finalName)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan file: " + err.Error(),
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal memulai transaksi: " + err.Error(),
		})
		return
	}

	_, err = tx.Exec("UPDATE laporan_100 SET status = ? WHERE id = ?", "on review", laporan100ID)
	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal mengubah status laporan_100: " + err.Error(),
		})
		return
	}

	var cycleNumber int
	err = tx.QueryRow(`
		SELECT COALESCE(MAX(cycle_number), 0) + 1 
		FROM review_laporan100_taruna 
		WHERE laporan100_id = ?`, laporan100ID).Scan(&cycleNumber)
	if err != nil {
		cycleNumber = 1
	}

	dosenIDInt, _ := strconv.Atoi(dosenID)

	_, err = tx.Exec(`
		INSERT INTO review_laporan100_taruna (
			laporan100_id, taruna_id, dosen_id, cycle_number,
			topik_penelitian, file_path, keterangan,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
		laporan100ID, tarunaID, dosenIDInt, cycleNumber,
		topikPenelitian, filePath, keterangan,
	)

	if err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan data revisi: " + err.Error(),
		})
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal commit transaksi: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Revisi Laporan 100% berhasil diunggah",
		"data": map[string]interface{}{
			"file_path": filePath,
		},
	})
}

// DownloadFileRevisiTarunaLaporan100Handler digunakan untuk mengunduh file revisi laporan 100% oleh taruna
func DownloadFileRevisiTarunaLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori file revisi taruna
	baseDir := "uploads/reviewlaporan100/taruna"

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
func GetRevisiLaporan100TarunaHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Content-Type", "application/json")

	userID := r.URL.Query().Get("taruna_id") // We receive user_id as taruna_id from frontend
	dosenID := r.URL.Query().Get("dosen_id")
	laporan100ID := r.URL.Query().Get("laporan100_id")

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
			rit.laporan100_id,
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
		FROM review_laporan100_taruna rit
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

	if laporan100ID != "" {
		query += " AND rit.laporan100_id = ?"
		args = append(args, laporan100ID)
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
			Laporan100ID    int
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
			&revision.Laporan100ID,
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
			"laporan100_id":    revision.Laporan100ID,
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
func GetReviewLaporan100DetailHandler(w http.ResponseWriter, r *http.Request) {
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
			r.id, r.laporan100_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna, d.nama_lengkap as dosen_nama
		FROM review_laporan100 r
		LEFT JOIN taruna t ON r.taruna_id = t.id
		LEFT JOIN dosen d ON r.dosen_id = d.id
		WHERE r.id = ?
	`

	var review entities.ReviewLaporan100
	var namaTaruna, dosenNama sql.NullString
	err = db.QueryRow(query, reviewID).Scan(
		&review.ID,
		&review.Laporan100ID,
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
func GetReviewLaporan100DosenDetailHandler(w http.ResponseWriter, r *http.Request) {
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
			r.id, r.laporan100_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna, d.nama_lengkap as nama_dosen,
			p.status as laporan100_status
		FROM review_laporan100 r
		LEFT JOIN taruna t ON r.taruna_id = t.id
		LEFT JOIN dosen d ON r.dosen_id = d.id
		LEFT JOIN laporan100 p ON r.laporan100_id = p.id
		WHERE r.id = ?
	`

	var review struct {
		ID               int            `json:"id"`
		Laporan100ID     int            `json:"laporan100_id"`
		TarunaID         int            `json:"taruna_id"`
		DosenID          int            `json:"dosen_id"`
		CycleNumber      int            `json:"cycle_number"`
		TopikPenelitian  string         `json:"topik_penelitian"`
		FilePath         string         `json:"file_path"`
		Keterangan       string         `json:"keterangan"`
		CreatedAt        string         `json:"created_at"`
		UpdatedAt        string         `json:"updated_at"`
		NamaTaruna       sql.NullString `json:"nama_taruna"`
		NamaDosen        sql.NullString `json:"nama_dosen"`
		Laporan100Status sql.NullString `json:"laporan100_status"`
	}

	err = db.QueryRow(query, reviewID).Scan(
		&review.ID,
		&review.Laporan100ID,
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
		&review.Laporan100Status,
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
		"id":                review.ID,
		"laporan100_id":     review.Laporan100ID,
		"taruna_id":         review.TarunaID,
		"dosen_id":          review.DosenID,
		"cycle_number":      review.CycleNumber,
		"topik_penelitian":  review.TopikPenelitian,
		"file_path":         review.FilePath,
		"keterangan":        review.Keterangan,
		"created_at":        review.CreatedAt,
		"updated_at":        review.UpdatedAt,
		"nama_taruna":       review.NamaTaruna.String,
		"nama_dosen":        review.NamaDosen.String,
		"laporan100_status": review.Laporan100Status.String,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   response,
	})
}
