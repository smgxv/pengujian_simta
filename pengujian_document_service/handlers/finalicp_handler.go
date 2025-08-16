package handlers

import (
	"database/sql"
	"document_service/config"
	"document_service/entities"
	"document_service/models"
	"document_service/utils/filemanager"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Handler untuk mengupload final ICP + file pendukung (wajib)
func UploadFinalICPHandler(w http.ResponseWriter, r *http.Request) {
	// ===== CORS =====
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// ===== Batas total payload (opsional) =====
	if r.ContentLength > filemanager.MaxFileSize*4 { // mis. 15MB * 4 = 60MB
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Total file terlalu besar. Maksimal 60MB",
		})
		return
	}

	// ===== Parse form =====
	if err := r.ParseMultipartForm(filemanager.MaxFileSize * 4); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Gagal parsing form data",
		})
		return
	}

	// ===== Ambil field =====
	userID := r.FormValue("user_id")
	namaLengkap := r.FormValue("nama_lengkap")
	jurusan := r.FormValue("jurusan")
	kelas := r.FormValue("kelas")
	topikPenelitian := r.FormValue("topik_penelitian")
	keterangan := r.FormValue("keterangan")

	if userID == "" || namaLengkap == "" || jurusan == "" || kelas == "" || topikPenelitian == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Missing required fields",
		})
		return
	}
	userIDInt, err := strconv.Atoi(userID)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "User ID tidak valid",
		})
		return
	}

	// ===== Konfigurasi validasi file =====
	maxSize := int64(15 * 1024 * 1024) // 15MB
	allowedFinalExt := map[string]bool{".pdf": true}
	allowedSupportExt := map[string]bool{
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	}
	hasAllowedExt := func(name string, allowed map[string]bool) bool {
		ext := strings.ToLower(filepath.Ext(name))
		return allowed[ext]
	}

	// ===== FINAL ICP (wajib, PDF) =====
	file, handler, err := r.FormFile("file")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "File final wajib diunggah: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// Ukuran
	if handler.Size > maxSize {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Ukuran file final melebihi 15MB",
		})
		return
	}
	// Ekstensi
	if !hasAllowedExt(handler.Filename, allowedFinalExt) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Tipe file final ICP tidak diizinkan (hanya PDF)",
		})
		return
	}
	// (Opsional) Content sniffing khusus PDF (pakai util kamu)
	if err := filemanager.ValidateFileType(file, handler.Filename); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	_, _ = file.Seek(0, 0)

	// Simpan final ICP
	safeFilename := filemanager.ValidateFileName(handler.Filename)
	finalName := fmt.Sprintf("FINAL_ICP_%s_%s_%s", userID, time.Now().Format("20060102150405"), safeFilename)
	finalDir := "uploads/finalicp"
	filePath, err := filemanager.SaveUploadedFile(file, handler, finalDir, finalName)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	// Kumpulan path untuk cleanup jika gagal
	savedPaths := []string{filePath}

	// ===== FILE PENDUKUNG (wajib minimal 1) =====
	supportFiles := r.MultipartForm.File["support_files[]"]
	if len(supportFiles) == 0 {
		_ = os.Remove(filePath)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Minimal 1 file pendukung wajib diunggah",
		})
		return
	}

	var supportPaths []string
	supportDir := "uploads/pendukungicp"

	for _, fh := range supportFiles {
		f, err := fh.Open()
		if err != nil {
			_ = os.Remove(filePath)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "Gagal membuka file pendukung: " + err.Error(),
			})
			return
		}

		// Ukuran
		if fh.Size > maxSize {
			f.Close()
			_ = os.Remove(filePath)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": fmt.Sprintf("Ukuran file pendukung melebihi 15MB (%s)", fh.Filename),
			})
			return
		}
		// Ekstensi
		if !hasAllowedExt(fh.Filename, allowedSupportExt) {
			f.Close()
			_ = os.Remove(filePath)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": fmt.Sprintf("Tipe file pendukung tidak diizinkan (%s). Hanya PDF, DOC, DOCX, XLS, XLSX.", fh.Filename),
			})
			return
		}
		// (Opsional) Sniffing — jika filemanager.ValidateFileType hanya untuk PDF,
		// biarkan ext check untuk DOC/XLS; tetap aman karena kita sanitize nama & batasi size.

		_, _ = f.Seek(0, 0)
		safeName := filemanager.ValidateFileName(fh.Filename)
		// Pakai timestamp high-res agar unik walau banyak file per detik
		supportName := fmt.Sprintf("%d_%s", time.Now().Unix(), safeName)

		outPath, err := filemanager.SaveUploadedFile(f, fh, supportDir, supportName)
		f.Close()
		if err != nil {
			_ = os.Remove(filePath)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
		savedPaths = append(savedPaths, outPath)
		supportPaths = append(supportPaths, outPath)
	}

	// ===== SIMPAN DB =====
	db, err := config.GetDB()
	if err != nil {
		for _, p := range savedPaths {
			_ = os.Remove(p)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Error connecting to database: " + err.Error(),
		})
		return
	}
	defer db.Close()

	finalICPModel := models.NewFinalICPModel(db)
	finalICP := &entities.FinalICP{
		UserID:          userIDInt,
		NamaLengkap:     namaLengkap,
		Jurusan:         jurusan,
		Kelas:           kelas,
		TopikPenelitian: topikPenelitian,
		FilePath:        filePath, // simpan path relatif/absolut sesuai kebijakanmu
		Keterangan:      keterangan,
	}

	// Set JSON array path pendukung
	if err := finalICP.SetSupportingFiles(supportPaths); err != nil {
		for _, p := range savedPaths {
			_ = os.Remove(p)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Gagal encode file pendukung: " + err.Error(),
		})
		return
	}

	if err := finalICPModel.Create(finalICP); err != nil {
		for _, p := range savedPaths {
			_ = os.Remove(p)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Error saving to database: " + err.Error(),
		})
		return
	}

	// ===== RESPONSE =====
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": "Final ICP dan file pendukung berhasil diunggah",
		"data": map[string]any{
			"id":                  finalICP.ID,
			"file_path":           filePath,
			"file_pendukung_path": supportPaths, // array path (bukan JSON string) untuk kenyamanan klien
		},
	})
}

// Handler untuk mengambil daftar final ICP berdasarkan user_id
func GetFinalICPHandler(w http.ResponseWriter, r *http.Request) {
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

	finalICPModel := models.NewFinalICPModel(db)
	finalICPs, err := finalICPModel.GetByUserID(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mapped := []map[string]interface{}{}
	for _, icp := range finalICPs {
		// Parse daftar path pendukung dari kolom JSON (aman jika kosong/invalid)
		var supportPaths []string
		if paths, err := icp.GetSupportingFiles(); err == nil && len(paths) > 0 {
			supportPaths = paths
		}

		// Buat URL download per index
		filePendukungURL := make([]string, 0, len(supportPaths))
		supportFiles := make([]map[string]interface{}, 0, len(supportPaths))
		for i, p := range supportPaths {
			url := fmt.Sprintf("/api/document/finalicp/download/%d?type=support&index=%d", icp.ID, i)
			filePendukungURL = append(filePendukungURL, url)

			name := filepath.Base(p)
			supportFiles = append(supportFiles, map[string]interface{}{
				"index": i,
				"name":  name,
				"url":   url,
			})
		}

		mapped = append(mapped, map[string]interface{}{
			"taruna_id":          icp.UserID,
			"nama_lengkap":       icp.NamaLengkap,
			"jurusan":            icp.Jurusan,
			"kelas":              icp.Kelas,
			"topik_penelitian":   icp.TopikPenelitian,
			"status":             icp.Status,
			"final_icp_id":       icp.ID, // penting untuk download by id
			"final_download_url": fmt.Sprintf("/api/document/finalicp/download/%d?type=final", icp.ID),

			// Kompatibilitas + kemudahan frontend:
			"file_pendukung_path": icp.FilePendukungPath, // string JSON asli dari DB (jika ingin)
			"file_pendukung_url":  filePendukungURL,      // array URL download
			"support_files":       supportFiles,          // array object {index,name,url}
		})
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   mapped,
	})
}

// Helper function to parse string to int
func parseInt(s string) int {
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}

// Handler untuk mengambil data gabungan taruna dan final ICP
func GetAllFinalICPWithTarunaHandler(w http.ResponseWriter, r *http.Request) {
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

	// Tambahkan kolom file_pendukung_path dari tabel final_icp
	query := `
		SELECT 
			t.user_id as taruna_id,
			t.nama_lengkap,
			t.jurusan,
			t.kelas,
			COALESCE(f.topik_penelitian, '') as topik_penelitian,
			COALESCE(f.status, '') as status,
			COALESCE(f.id, 0) as final_icp_id,
			COALESCE(f.file_pendukung_path, '') as file_pendukung_path
		FROM taruna t
		LEFT JOIN final_icp f ON t.user_id = f.user_id
		ORDER BY t.nama_lengkap ASC
	`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TarunaICP struct {
		TarunaID         int    `json:"taruna_id"`
		NamaLengkap      string `json:"nama_lengkap"`
		Jurusan          string `json:"jurusan"`
		Kelas            string `json:"kelas"`
		TopikPenelitian  string `json:"topik_penelitian"`
		Status           string `json:"status"`
		FinalICPID       int    `json:"final_icp_id"`
		FilePendukungRaw string `json:"file_pendukung_path"`
	}

	var results []TarunaICP
	for rows.Next() {
		var data TarunaICP
		if err := rows.Scan(
			&data.TarunaID,
			&data.NamaLengkap,
			&data.Jurusan,
			&data.Kelas,
			&data.TopikPenelitian,
			&data.Status,
			&data.FinalICPID,
			&data.FilePendukungRaw,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		results = append(results, data)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   results,
	})
}

// Handler untuk update status Final ICP
func UpdateFinalICPStatusHandler(w http.ResponseWriter, r *http.Request) {
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

	query := "UPDATE final_icp SET status = ? WHERE id = ?"
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

// Handler untuk download file Final ICP atau file pendukung
func DownloadFinalICPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	icpID := vars["id"]

	fileType := r.URL.Query().Get("type")    // "final" atau "support"
	supportIdx := r.URL.Query().Get("index") // index untuk file pendukung

	if fileType == "" {
		fileType = "final"
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var filePath string

	if fileType == "final" {
		// Ambil path file final
		query := "SELECT file_path FROM final_icp WHERE id = ?"
		err = db.QueryRow(query, icpID).Scan(&filePath)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "File not found", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	} else if fileType == "support" {
		// Ambil JSON file pendukung
		var filePendukungJSON string
		query := "SELECT file_pendukung_path FROM final_icp WHERE id = ?"
		err = db.QueryRow(query, icpID).Scan(&filePendukungJSON)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "File pendukung tidak ditemukan", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Decode JSON ke slice
		var paths []string
		if err := json.Unmarshal([]byte(filePendukungJSON), &paths); err != nil {
			http.Error(w, "Gagal membaca data file pendukung", http.StatusInternalServerError)
			return
		}

		// Ambil index
		idx, err := strconv.Atoi(supportIdx)
		if err != nil || idx < 0 || idx >= len(paths) {
			http.Error(w, "Index file pendukung tidak valid", http.StatusBadRequest)
			return
		}

		filePath = paths[idx]
	} else {
		http.Error(w, "Tipe file tidak valid", http.StatusBadRequest)
		return
	}

	// Pastikan file ada
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	fileName := filepath.Base(filePath)
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeFile(w, r, filePath)
}

// Handler untuk mengatur penelaah ICP
func SetPenelaahICPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var requestData struct {
		FinalICPID  int    `json:"final_icp_id"`
		UserID      int    `json:"user_id"`          // Taruna
		Penelaah1ID int    `json:"penelaah1_id"`     // Dosen 1
		Penelaah2ID int    `json:"penelaah2_id"`     // Dosen 2
		Topik       string `json:"topik_penelitian"` // Bisa diambil dari final_icp jika perlu
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

	// Cek apakah sudah ada entri penelaah untuk final_icp_id tersebut
	var existingID int
	checkQuery := `SELECT id FROM penelaah_icp WHERE final_icp_id = ?`
	err = db.QueryRow(checkQuery, requestData.FinalICPID).Scan(&existingID)

	if err != nil && err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err == sql.ErrNoRows {
		// Insert baru
		insertQuery := `
			INSERT INTO penelaah_icp (final_icp_id, user_id, penelaah_1_id, penelaah_2_id, topik_penelitian)
			VALUES (?, ?, ?, ?, ?)
		`
		_, err = db.Exec(insertQuery, requestData.FinalICPID, requestData.UserID, requestData.Penelaah1ID, requestData.Penelaah2ID, requestData.Topik)
	} else {
		// Update yang sudah ada
		updateQuery := `
			UPDATE penelaah_icp 
			SET penelaah_1_id = ?, penelaah_2_id = ?, topik_penelitian = ?, updated_at = CURRENT_TIMESTAMP 
			WHERE final_icp_id = ?
		`
		_, err = db.Exec(updateQuery, requestData.Penelaah1ID, requestData.Penelaah2ID, requestData.Topik, requestData.FinalICPID)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Penelaah berhasil diatur",
	})
}
