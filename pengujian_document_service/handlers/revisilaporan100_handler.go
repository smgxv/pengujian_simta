package handlers

import (
	"database/sql"
	"document_service/config"
	"document_service/entities"
	"document_service/models"
	"document_service/utils"
	"document_service/utils/filemanager"
	"document_service/utils/produkmanager"
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
func UploadRevisiLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	// CORS setup
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	err := r.ParseMultipartForm(produkmanager.MaxProdukSize)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Form tidak valid atau file terlalu besar: " + err.Error(),
		})
		return
	}

	// Ambil data form
	userID := r.FormValue("user_id")
	namaLengkap := r.FormValue("nama_lengkap")
	jurusan := r.FormValue("jurusan")
	kelas := r.FormValue("kelas")
	tahunAkademik := r.FormValue("tahun_akademik")
	topikPenelitian := r.FormValue("topik_penelitian")
	abstrakID := r.FormValue("abstrak_id")
	abstrakEN := r.FormValue("abstrak_en")
	kataKunci := r.FormValue("kata_kunci")
	linkRepo := r.FormValue("link_repo")
	keterangan := r.FormValue("keterangan")

	if userID == "" || namaLengkap == "" || topikPenelitian == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	uploadDir := "uploads/finallaporan100"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal membuat direktori upload: " + err.Error(),
		})
		return
	}

	timestamp := time.Now().Format("20060102150405")

	// === UPLOAD FILE UTAMA (PDF) ===
	var filePath string
	file, handler, err := r.FormFile("file_laporan")
	if err == nil {
		defer file.Close()

		// Validasi file PDF
		if err := filemanager.ValidateFileType(file, handler.Filename); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
		file.Seek(0, 0)

		safeName := filemanager.ValidateFileName(handler.Filename)
		filename := fmt.Sprintf("FINAL_LAPORAN100_%s_%s_%s", userID, timestamp, safeName)

		filePath, err = filemanager.SaveUploadedFile(file, handler, uploadDir, filename)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
	}

	// === UPLOAD FILE PRODUK TA ===
	var fileProdukPath string
	produkFile, produkHandler, err := r.FormFile("file_produk_ta")
	if err == nil {
		defer produkFile.Close()

		if err := produkmanager.ValidateProdukFileType(produkHandler.Filename); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
		produkFile.Seek(0, 0)

		safeName := filemanager.ValidateFileName(produkHandler.Filename)
		produkFilename := fmt.Sprintf("PRODUK_TA_%s_%s_%s", userID, timestamp, safeName)

		fileProdukPath, err = produkmanager.SaveProdukFile(produkFile, produkHandler, uploadDir, produkFilename)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
	}

	// === UPLOAD FILE BAP ===
	var fileBapPath string
	bapFile, bapHandler, err := r.FormFile("file_bap")
	if err == nil {
		defer bapFile.Close()

		if err := filemanager.ValidateFileType(bapFile, bapHandler.Filename); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
		bapFile.Seek(0, 0)

		safeName := filemanager.ValidateFileName(bapHandler.Filename)
		bapFilename := fmt.Sprintf("BAP_%s_%s_%s", userID, timestamp, safeName)

		fileBapPath, err = filemanager.SaveUploadedFile(bapFile, bapHandler, uploadDir, bapFilename)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			})
			return
		}
	}

	// === Simpan ke Database ===
	db, err := config.GetDB()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal koneksi database: " + err.Error(),
		})
		return
	}
	defer db.Close()

	revisi := &entities.RevisiLaporan100{
		UserID:          utils.ParseInt(userID),
		NamaLengkap:     namaLengkap,
		Jurusan:         jurusan,
		Kelas:           kelas,
		TahunAkademik:   tahunAkademik,
		TopikPenelitian: topikPenelitian,
		AbstrakID:       abstrakID,
		AbstrakEN:       abstrakEN,
		KataKunci:       kataKunci,
		LinkRepo:        linkRepo,
		FilePath:        filePath,
		FileProdukPath:  fileProdukPath,
		FileBapPath:     fileBapPath,
		Keterangan:      keterangan,
	}

	model := models.NewRevisiLaporan100Model(db)
	if err := model.Create(revisi); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan ke database: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Revisi laporan berhasil diunggah",
		"data": map[string]interface{}{
			"id":               revisi.ID,
			"file_path":        revisi.FilePath,
			"file_produk_path": revisi.FileProdukPath,
			"file_bap_path":    revisi.FileBapPath,
		},
	})
}

// DownloadFileRevisiLaporan100Handler digunakan untuk mengunduh file revisi final laporan 100 taruna
func DownloadFileRevisiLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")

	// Direktori penyimpanan file revisi
	baseDir := "uploads/revisifinallaporan100"

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

// Handler untuk mengambil daftar revisi proposal berdasarkan user_id
func GetRevisiLaporan100Handler(w http.ResponseWriter, r *http.Request) {
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

	revisiLaporan100Model := models.NewRevisiLaporan100Model(db)
	revisiLaporan100s, err := revisiLaporan100Model.GetByUserID(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   revisiLaporan100s,
	})
}

// Handler untuk mengambil data gabungan taruna dan revisi proposal
func GetAllRevisiLaporan100WithTarunaHandler(w http.ResponseWriter, r *http.Request) {
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
			COALESCE(f.id, 0) as revisi_laporan100_id
		FROM taruna t
		LEFT JOIN revisi_laporan100 f ON t.user_id = f.user_id
		ORDER BY t.nama_lengkap ASC`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TarunaLaporan100 struct {
		TarunaID           int    `json:"taruna_id"`
		NamaLengkap        string `json:"nama_lengkap"`
		Jurusan            string `json:"jurusan"`
		Kelas              string `json:"kelas"`
		TopikPenelitian    string `json:"topik_penelitian"`
		Status             string `json:"status"`
		RevisiLaporan100ID int    `json:"revisi_laporan100_id"`
	}

	var results []TarunaLaporan100
	for rows.Next() {
		var data TarunaLaporan100
		err := rows.Scan(
			&data.TarunaID,
			&data.NamaLengkap,
			&data.Jurusan,
			&data.Kelas,
			&data.TopikPenelitian,
			&data.Status,
			&data.RevisiLaporan100ID,
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
func UpdateRevisiLaporan100StatusHandler(w http.ResponseWriter, r *http.Request) {
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

	query := "UPDATE revisi_laporan100 SET status = ? WHERE id = ?"
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
func DownloadRevisiLaporan100Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]
	tipe := r.URL.Query().Get("tipe") // "laporan", "produk", "bap"
	if tipe == "" {
		tipe = "laporan" // default
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var filePath string
	switch tipe {
	case "produk":
		err = db.QueryRow("SELECT file_produk_path FROM revisi_laporan100 WHERE id = ?", id).Scan(&filePath)
	case "bap":
		err = db.QueryRow("SELECT file_bap_path FROM revisi_laporan100 WHERE id = ?", id).Scan(&filePath)
	default:
		err = db.QueryRow("SELECT file_path FROM revisi_laporan100 WHERE id = ?", id).Scan(&filePath)
	}

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
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeFile(w, r, filePath)
}
