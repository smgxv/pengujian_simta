package handlers

import (
	"database/sql"
	"document_service/config"
	"document_service/utils/filemanager"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type HasilTelaahLaporan70 struct {
	ID              int    `json:"id"`
	NamaDosen       string `json:"nama_dosen"`
	TopikPenelitian string `json:"topik_penelitian"`
	FilePath        string `json:"file_path"`
	SubmittedAt     string `json:"submitted_at"`
}

// GetSeminarLaporan70ByDosenHandler menangani request untuk mendapatkan data seminar laporan70 berdasarkan ID dosen
func GetSeminarLaporan70ByDosenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	dosenID := r.URL.Query().Get("dosen_id")
	if dosenID == "" {
		http.Error(w, "Dosen ID is required", http.StatusBadRequest)
		return
	}

	dosenIDInt, err := strconv.Atoi(dosenID)
	if err != nil {
		http.Error(w, "Invalid dosen ID", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Tambahkan file_pendukung_path di SELECT
	query := `
		SELECT fl.id, fl.user_id, fl.topik_penelitian, fl.file_path, fl.file_pendukung_path, u.nama_lengkap
		FROM final_laporan70 fl
		JOIN users u ON fl.user_id = u.id
		JOIN penguji_laporan70 pl ON fl.id = pl.final_laporan70_id
		WHERE pl.penguji_1_id = ? OR pl.penguji_2_id = ?
	`

	// Kirim hanya 2 parameter sesuai jumlah placeholder
	rows, err := db.Query(query, dosenIDInt, dosenIDInt)
	if err != nil {
		http.Error(w, "Error querying database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type FinalLaporan70Data struct {
		FinalLaporan70ID  int    `json:"final_laporan70_id"`
		UserID            int    `json:"user_id"`
		TopikPenelitian   string `json:"topik_penelitian"`
		FilePath          string `json:"file_path"`
		FilePendukungPath string `json:"file_pendukung_path"`
		TarunaNama        string `json:"taruna_nama"`
	}

	var data []FinalLaporan70Data
	for rows.Next() {
		var item FinalLaporan70Data
		err := rows.Scan(
			&item.FinalLaporan70ID,
			&item.UserID,
			&item.TopikPenelitian,
			&item.FilePath,
			&item.FilePendukungPath,
			&item.TarunaNama,
		)
		if err != nil {
			http.Error(w, "Error scanning data: "+err.Error(), http.StatusInternalServerError)
			return
		}
		data = append(data, item)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Error reading rows: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   data,
	})
}

// GetTarunaListForDosenHandler menangani request untuk mendapatkan daftar taruna yang belum memiliki final laporan70
func GetSeminarLaporan70TarunaListForDosenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	dosenID := r.URL.Query().Get("dosen_id")
	if dosenID == "" {
		http.Error(w, "Dosen ID is required", http.StatusBadRequest)
		return
	}

	dosenIDInt, err := strconv.Atoi(dosenID)
	if err != nil {
		http.Error(w, "Invalid dosen ID", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := `
		SELECT DISTINCT 
			pp.user_id, 
			t.nama_lengkap, 
			fp.topik_penelitian,
			fp.id AS final_laporan70_id
		FROM penguji_laporan70 pp
		JOIN taruna t ON pp.user_id = t.user_id
		LEFT JOIN final_laporan70 fp ON fp.user_id = t.user_id
		WHERE 
			pp.penguji_1_id = ? 
			OR pp.penguji_2_id = ?
	`

	rows, err := db.Query(query, dosenIDInt, dosenIDInt)
	if err != nil {
		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TarunaData struct {
		UserID           int    `json:"user_id"`
		NamaLengkap      string `json:"nama_lengkap"`
		TopikPenelitian  string `json:"topik_penelitian"`
		FinalLaporan70ID int    `json:"final_laporan70_id"`
	}

	var tarunaList []TarunaData
	for rows.Next() {
		var t TarunaData
		err := rows.Scan(&t.UserID, &t.NamaLengkap, &t.TopikPenelitian, &t.FinalLaporan70ID)
		if err != nil {
			http.Error(w, "Error reading rows: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tarunaList = append(tarunaList, t)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   tarunaList,
	})
}

// PenilaianLaporan70Handler menangani request untuk menyimpan penilaian laporan70 (multi-file untuk penilaian)
func PenilaianLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	sendError := func(message string, statusCode int) {
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": message,
		})
	}

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Izinkan total payload lebih besar untuk multi-file (tetap batasi 15MB per file di bawah)
	if r.ContentLength > filemanager.MaxFileSize { // contoh: total ≤ 150MB
		sendError("Total upload terlalu besar. Batas 15MB per file.", http.StatusBadRequest)
		return
	}

	// Parse multipart dengan kuota lebih besar agar memadai untuk multi-file
	if err := r.ParseMultipartForm(filemanager.MaxFileSize); err != nil {
		sendError("Error parsing form: "+err.Error(), http.StatusBadRequest)
		return
	}

	userID := r.FormValue("user_id")
	dosenID := r.FormValue("dosen_id")
	finalLaporan70ID := r.FormValue("final_laporan70_id")

	if userID == "" || dosenID == "" || finalLaporan70ID == "" {
		sendError("user_id, dosen_id, dan final_laporan70_id harus diisi", http.StatusBadRequest)
		return
	}

	// ====================== TIDAK DIUBAH: Upload Hasil Telaah (single file) ======================
	hasiltelaahFile, hasiltelaahHeader, err := r.FormFile("hasiltelaah_file")
	if err != nil {
		sendError("Gagal mengambil file Hasil Telaah: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer hasiltelaahFile.Close()

	if err := filemanager.ValidateFileType(hasiltelaahFile, hasiltelaahHeader.Filename); err != nil {
		sendError(err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = hasiltelaahFile.Seek(0, 0)

	hasiltelaahFilename := fmt.Sprintf(
		"Hasil_Telaah_%s_%s_%s",
		userID,
		time.Now().Format("20060102150405"),
		filemanager.ValidateFileName(hasiltelaahHeader.Filename),
	)

	hasiltelaahPath, err := filemanager.SaveUploadedFile(
		hasiltelaahFile,
		hasiltelaahHeader,
		"uploads/hasiltelaah_laporan70",
		hasiltelaahFilename,
	)
	if err != nil {
		sendError("Gagal menyimpan file hasil telaah: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ====================== DIUBAH: Upload File Penilaian (multi-file) ======================
	// Ambil daftar file dari key "penilaian_file[]" (fallback ke "penilaian_file" jika perlu)
	var penilaianHeaders []*multipart.FileHeader
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		if files, ok := r.MultipartForm.File["penilaian_file[]"]; ok {
			penilaianHeaders = files
		} else if files, ok := r.MultipartForm.File["penilaian_file"]; ok {
			penilaianHeaders = files // dukung nama lama jika masih digunakan
		}
	}
	if len(penilaianHeaders) == 0 {
		_ = os.Remove(hasiltelaahPath)
		sendError("Gagal mengambil file penilaian: tidak ada file yang diunggah", http.StatusBadRequest)
		return
	}

	// Validasi dan simpan setiap file penilaian (tanpa filemanager.ValidateFileType)
	allowedExt := map[string]bool{
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	}
	var penilaianPaths []string
	var savedFiles []string // untuk cleanup jika gagal di tengah

	nowStr := time.Now().Format("20060102150405")

	for idx, hdr := range penilaianHeaders {
		// Batas ukuran per-file 15MB
		if hdr.Size > filemanager.MaxFileSize {
			_ = os.Remove(hasiltelaahPath)
			for _, p := range savedFiles {
				_ = os.Remove(p)
			}
			sendError(fmt.Sprintf("Ukuran file '%s' melebihi 15MB", hdr.Filename), http.StatusBadRequest)
			return
		}

		// Validasi ekstensi (tanpa filemanager)
		ext := strings.ToLower(filepath.Ext(hdr.Filename))
		if !allowedExt[ext] {
			_ = os.Remove(hasiltelaahPath)
			for _, p := range savedFiles {
				_ = os.Remove(p)
			}
			sendError(fmt.Sprintf("Tipe file tidak didukung untuk '%s'. Hanya pdf, doc, docx, xls, xlsx.", hdr.Filename), http.StatusBadRequest)
			return
		}

		// Buka file
		f, err := hdr.Open()
		if err != nil {
			_ = os.Remove(hasiltelaahPath)
			for _, p := range savedFiles {
				_ = os.Remove(p)
			}
			sendError("Gagal membuka file penilaian: "+err.Error(), http.StatusBadRequest)
			return
		}

		// (Opsional) Anda bisa menambahkan sniff ringan sendiri jika ingin:
		// buf := make([]byte, 512)
		// n, _ := f.Read(buf)
		// mimeGuess := http.DetectContentType(buf[:n])
		// _, _ = f.Seek(0, io.SeekStart)

		// Buat nama file unik (tambahkan index untuk beda file dalam batch)
		penilaianFilename := fmt.Sprintf(
			"File_Penilaian_%s_%s_%02d_%s",
			userID,
			nowStr,
			idx+1,
			filemanager.ValidateFileName(hdr.Filename),
		)

		savedPath, err := filemanager.SaveUploadedFile(
			f,
			hdr,
			"uploads/file_penilaian_laporan70",
			penilaianFilename,
		)
		f.Close()
		if err != nil {
			_ = os.Remove(hasiltelaahPath)
			for _, p := range savedFiles {
				_ = os.Remove(p)
			}
			sendError("Gagal menyimpan salah satu file penilaian: "+err.Error(), http.StatusInternalServerError)
			return
		}

		penilaianPaths = append(penilaianPaths, savedPath)
		savedFiles = append(savedFiles, savedPath)
	}

	// JSON-encode daftar path agar bisa disimpan ke kolom string tanpa ubah skema
	penilaianPathsJSON, err := json.Marshal(penilaianPaths)
	if err != nil {
		_ = os.Remove(hasiltelaahPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal menyiapkan data file penilaian: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ====================== Database ======================
	db, err := config.GetDB()
	if err != nil {
		_ = os.Remove(hasiltelaahPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Koneksi database gagal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		_ = os.Remove(hasiltelaahPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal memulai transaksi: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var exists bool
	err = tx.QueryRow(`SELECT EXISTS(
		SELECT 1 FROM seminar_laporan70_penilaian 
		WHERE user_id = ? AND dosen_id = ? AND final_laporan70_id = ?
	)`, userID, dosenID, finalLaporan70ID).Scan(&exists)
	if err != nil {
		tx.Rollback()
		_ = os.Remove(hasiltelaahPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal cek data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		_, err = tx.Exec(`UPDATE seminar_laporan70_penilaian 
			SET file_hasiltelaah_path = ?, file_penilaian_path = ?, 
				submitted_at = NOW(), status_pengumpulan = 'sudah' 
			WHERE user_id = ? AND dosen_id = ? AND final_laporan70_id = ?`,
			hasiltelaahPath, string(penilaianPathsJSON), userID, dosenID, finalLaporan70ID)
	} else {
		_, err = tx.Exec(`INSERT INTO seminar_laporan70_penilaian (
			user_id, final_laporan70_id, dosen_id,
			file_hasiltelaah_path, file_penilaian_path,
			status_pengumpulan, submitted_at
		) VALUES (?, ?, ?, ?, ?, 'sudah', NOW())`,
			userID, finalLaporan70ID, dosenID, hasiltelaahPath, string(penilaianPathsJSON))
	}
	if err != nil {
		tx.Rollback()
		_ = os.Remove(hasiltelaahPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal menyimpan data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		_ = os.Remove(hasiltelaahPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal commit data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Penilaian laporan 70% berhasil disimpan",
		"data": map[string]interface{}{
			"hasiltelaah_path": hasiltelaahPath,
			"penilaian_paths":  penilaianPaths, // kirim array agar mudah dipakai di frontend
		},
	})
}

// DownloadFilePenilaianLaporan70Handler digunakan untuk mengunduh file Catatan Perbaikan atau Penilaian Lainnya Laporan70
func DownloadFilePenilaianLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Ambil nama file dari query
	rawPath := r.URL.Query().Get("path")
	if rawPath == "" {
		http.Error(w, "Parameter 'path' wajib diisi", http.StatusBadRequest)
		return
	}

	fileName := filepath.Base(rawPath) // cegah path traversal

	// Tentukan direktori berdasarkan prefix nama file
	var baseDir string
	switch {
	case strings.HasPrefix(fileName, "Hasil_Telaah_"):
		// (TETAP) dipakai oleh taruna untuk unduh hasil telaah
		baseDir = "uploads/hasiltelaah_laporan70"

	case strings.HasPrefix(fileName, "File_Penilaian_"):
		// (DISESUAIKAN) lokasi multi-file penilaian sesuai handler upload
		baseDir = "uploads/file_penilaian_laporan70"

	default:
		http.Error(w, "Prefix nama file tidak valid", http.StatusForbidden)
		return
	}

	// Bangun path absolut yang aman
	joinedPath := filepath.Join(baseDir, fileName)
	absPath, err := filepath.Abs(joinedPath)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	baseAbs, err := filepath.Abs(baseDir)
	if err != nil || !strings.HasPrefix(absPath, baseAbs) {
		http.Error(w, "Unauthorized file path", http.StatusForbidden)
		return
	}

	// Buka file
	f, err := os.Open(absPath)
	if err != nil {
		http.Error(w, "File tidak ditemukan", http.StatusNotFound)
		return
	}
	defer f.Close()

	// Tentukan content-type berdasarkan ekstensi
	ext := strings.ToLower(filepath.Ext(fileName))
	contentType := "application/octet-stream"
	switch ext {
	case ".pdf":
		contentType = "application/pdf"
	case ".doc":
		contentType = "application/msword"
	case ".docx":
		contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xls":
		contentType = "application/vnd.ms-excel"
	case ".xlsx":
		contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}

	// Header untuk download
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))

	if _, err := io.Copy(w, f); err != nil {
		http.Error(w, "Gagal mengirim file", http.StatusInternalServerError)
		return
	}
}

// Helper function untuk menyimpan file
func saveFile(src io.Reader, destPath string) error {
	dst, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func GetMonitoringPenilaianLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := `
				SELECT
			fp.id AS final_laporan70_id,
			u.nama_lengkap AS nama_taruna,
			t.jurusan,
			fp.topik_penelitian,
			d1.nama_lengkap AS penguji1,
			d2.nama_lengkap AS penguji2,
			CASE
				WHEN COUNT(DISTINCT
					CASE
					WHEN spp.dosen_id IN (pp.penguji_1_id, pp.penguji_2_id)
					AND spp.file_penilaian_path IS NOT NULL
					AND spp.status_pengumpulan = 'sudah'
					THEN spp.dosen_id
					END
				) = 2 THEN 'Lengkap'
				ELSE 'Belum Lengkap'
			END AS status_kelengkapan
		FROM penguji_laporan70 pp
		JOIN final_laporan70 fp ON fp.id = pp.final_laporan70_id
		JOIN users u ON u.id = pp.user_id
		JOIN taruna t ON t.user_id = u.id
		JOIN dosen d1 ON d1.id = pp.penguji_1_id
		JOIN dosen d2 ON d2.id = pp.penguji_2_id
		LEFT JOIN seminar_laporan70_penilaian spp
			ON spp.final_laporan70_id = pp.final_laporan70_id
		GROUP BY
			fp.id, u.nama_lengkap, t.jurusan, fp.topik_penelitian,
			d1.nama_lengkap, d2.nama_lengkap;

	`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Error querying database",
		})
		return
	}
	defer rows.Close()

	type MonitoringData struct {
		FinalLaporan70ID  int    `json:"final_laporan70_id"`
		NamaTaruna        string `json:"nama_taruna"`
		Jurusan           string `json:"jurusan"`
		TopikPenelitian   string `json:"topik_penelitian"`
		Penguji1          string `json:"penguji1"`
		Penguji2          string `json:"penguji2"`
		StatusKelengkapan string `json:"status_kelengkapan"`
	}

	var result []MonitoringData
	for rows.Next() {
		var m MonitoringData
		err := rows.Scan(
			&m.FinalLaporan70ID,
			&m.NamaTaruna,
			&m.Jurusan,
			&m.TopikPenelitian,
			&m.Penguji1,
			&m.Penguji2,
			&m.StatusKelengkapan,
		)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}
		result = append(result, m)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Error iterating rows: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Error reading data",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   result,
	})
}

func GetFinalLaporan70DetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	finalLaporan70ID := vars["id"]
	if finalLaporan70ID == "" {
		http.Error(w, "Final Laporan70 ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// --- Ambil info laporan70 + taruna ---
	queryLaporan70 := `
		SELECT fp.id, u.nama_lengkap, u.jurusan, u.kelas, fp.topik_penelitian
		FROM final_laporan70 fp
		JOIN users u ON u.id = fp.user_id
		WHERE fp.id = ?
	`
	var (
		idLaporan70     int
		namaTaruna      string
		jurusan         string
		kelas           string
		topikPenelitian string
	)
	err = db.QueryRow(queryLaporan70, finalLaporan70ID).Scan(&idLaporan70, &namaTaruna, &jurusan, &kelas, &topikPenelitian)
	if err != nil {
		http.Error(w, "Laporan70 tidak ditemukan: "+err.Error(), http.StatusNotFound)
		return
	}

	// --- Ambil id para penguji ---
	queryPenguji := `
		SELECT penguji_1_id, penguji_2_id
		FROM penguji_laporan70
		WHERE final_laporan70_id = ?
		LIMIT 1
	`
	var penguji1ID, penguji2ID int
	err = db.QueryRow(queryPenguji, finalLaporan70ID).Scan(&penguji1ID, &penguji2ID)
	if err != nil {
		http.Error(w, "Data penguji tidak ditemukan: "+err.Error(), http.StatusNotFound)
		return
	}

	type PenilaianDetail struct {
		NamaDosen         string   `json:"nama_dosen"`
		StatusPengumpulan string   `json:"status_pengumpulan"`
		FileHasilTelaah   string   `json:"file_hasiltelaah"`
		PenilaianPaths    []string `json:"penilaian_paths"`
	}

	getNamaDosen := func(dosenID int) string {
		var nama string
		if err := db.QueryRow(`SELECT nama_lengkap FROM dosen WHERE id = ?`, dosenID).Scan(&nama); err != nil {
			return "-"
		}
		return nama
	}

	getPenilaian := func(dosenID int) PenilaianDetail {
		namaDosen := getNamaDosen(dosenID)

		var (
			status            sql.NullString
			fileHasilTelaahNS sql.NullString
			filePenilaianNS   sql.NullString
		)

		err := db.QueryRow(`
			SELECT status_pengumpulan, file_hasiltelaah_path, file_penilaian_path
			FROM seminar_laporan70_penilaian
			WHERE final_laporan70_id = ? AND dosen_id = ?
			LIMIT 1
		`, finalLaporan70ID, dosenID).Scan(&status, &fileHasilTelaahNS, &filePenilaianNS)

		if err != nil {
			return PenilaianDetail{
				NamaDosen:         namaDosen,
				StatusPengumpulan: "belum",
				FileHasilTelaah:   "",
				PenilaianPaths:    []string{},
			}
		}

		var paths []string
		if filePenilaianNS.Valid && strings.TrimSpace(filePenilaianNS.String) != "" && strings.TrimSpace(filePenilaianNS.String) != "[]" {
			if err := json.Unmarshal([]byte(filePenilaianNS.String), &paths); err != nil {
				paths = []string{filePenilaianNS.String}
			}
		} else {
			paths = []string{}
		}

		return PenilaianDetail{
			NamaDosen:         namaDosen,
			StatusPengumpulan: ternaryLaporan70(status.Valid && status.String != "", status.String, "belum"),
			FileHasilTelaah:   ternaryLaporan70(fileHasilTelaahNS.Valid, fileHasilTelaahNS.String, ""),
			PenilaianPaths:    paths,
		}
	}

	resp := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"nama_taruna":      namaTaruna,
			"jurusan":          jurusan,
			"kelas":            kelas,
			"topik_penelitian": topikPenelitian,
			"penguji1":         getPenilaian(penguji1ID),
			"penguji2":         getPenilaian(penguji2ID),
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// helper kecil biar rapi (ternaryLaporan70-like)
func ternaryLaporan70[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

// Helper function untuk mendapatkan data penilaian dosen
func getPengujiLaporan70Data(db *sql.DB, laporan70ID string, dosenID int) map[string]interface{} {
	query := `
		SELECT 
			d.nama_lengkap,
			spp.file_penilaian_path,
			spp.file_berita_acara_path,
			spp.status_pengumpulan
		FROM dosen d
		LEFT JOIN seminar_laporan70_penilaian spp ON spp.dosen_id = d.id 
			AND spp.seminar_laporan70_id = ?
		WHERE d.id = ?
	`

	var data struct {
		NamaLengkap       string
		FilePenilaianPath sql.NullString
		BeritaAcaraPath   sql.NullString
		StatusPengumpulan sql.NullString
	}

	err := db.QueryRow(query, laporan70ID, dosenID).Scan(
		&data.NamaLengkap,
		&data.FilePenilaianPath,
		&data.BeritaAcaraPath,
		&data.StatusPengumpulan,
	)

	if err != nil {
		return map[string]interface{}{
			"nama_lengkap":           "-",
			"file_penilaian_path":    "",
			"file_berita_acara_path": "",
			"status_pengumpulan":     "belum",
		}
	}

	return map[string]interface{}{
		"nama_lengkap":           data.NamaLengkap,
		"file_penilaian_path":    data.FilePenilaianPath.String,
		"file_berita_acara_path": data.BeritaAcaraPath.String,
		"status_pengumpulan":     data.StatusPengumpulan.String,
	}
}

func GetHasilTelaahTarunaLaporan70Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Ambil user_id dari query
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "User ID is required",
		})
		return
	}

	// Koneksi ke DB
	db, err := config.GetDB()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Database connection error: " + err.Error(),
		})
		return
	}
	defer db.Close()

	// Query ambil hasil telaah
	query := `
		SELECT spp.id, d.nama_lengkap, fp.topik_penelitian, spp.file_hasiltelaah_path, spp.submitted_at
		FROM seminar_laporan70_penilaian spp
		JOIN dosen d ON spp.dosen_id = d.id
		LEFT JOIN final_laporan70 fp ON spp.final_laporan70_id = fp.id
		WHERE spp.user_id = ? AND spp.status_pengumpulan = 'sudah'
		ORDER BY spp.submitted_at DESC
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Query error: " + err.Error(),
		})
		return
	}
	defer rows.Close()

	var results []HasilTelaahLaporan70
	for rows.Next() {
		var c HasilTelaahLaporan70
		err := rows.Scan(&c.ID, &c.NamaDosen, &c.TopikPenelitian, &c.FilePath, &c.SubmittedAt)
		if err != nil {
			continue // skip baris yang gagal diparse
		}
		results = append(results, c)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   results,
	})
}
