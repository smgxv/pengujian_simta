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

type CatatanPerbaikanLaporan100 struct {
	ID              int    `json:"id"`
	NamaDosen       string `json:"nama_dosen"`
	TopikPenelitian string `json:"topik_penelitian"`
	FilePath        string `json:"file_path"`
	SubmittedAt     string `json:"submitted_at"`
}

// GetSeminarLaporan100ByDosenHandler menangani request untuk mendapatkan data seminar laporan100 berdasarkan ID dosen
func GetSeminarLaporan100ByDosenHandler(w http.ResponseWriter, r *http.Request) {
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
		SELECT 
			fp.id, 
			fp.user_id, 
			fp.topik_penelitian, 
			fp.file_path, 
			COALESCE(fp.file_pendukung_path, '') AS file_pendukung_path,
			u.nama_lengkap
		FROM final_laporan100 fp
		JOIN users u ON fp.user_id = u.id
		JOIN penguji_laporan100 pp ON fp.id = pp.final_laporan100_id
		WHERE pp.ketua_penguji_id = ? 
		   OR pp.penguji_1_id = ? 
		   OR pp.penguji_2_id = ?
	`

	// Kirim hanya 3 parameter sesuai jumlah placeholder
	rows, err := db.Query(query, dosenIDInt, dosenIDInt, dosenIDInt)
	if err != nil {
		http.Error(w, "Error querying database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type FinalLaporan100Data struct {
		FinalLaporan100ID int    `json:"final_laporan100_id"`
		UserID            int    `json:"user_id"`
		TopikPenelitian   string `json:"topik_penelitian"`
		FilePath          string `json:"file_path"`
		FilePendukungPath string `json:"file_pendukung_path"`
		TarunaNama        string `json:"taruna_nama"`
	}

	var data []FinalLaporan100Data
	for rows.Next() {
		var item FinalLaporan100Data
		err := rows.Scan(
			&item.FinalLaporan100ID,
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

// GetTarunaListForDosenHandler menangani request untuk mendapatkan daftar taruna yang belum memiliki final laporan100
func GetSeminarLaporan100TarunaListForDosenHandler(w http.ResponseWriter, r *http.Request) {
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
			fp.id AS final_laporan100_id
		FROM penguji_laporan100 pp
		JOIN taruna t ON pp.user_id = t.user_id
		LEFT JOIN final_laporan100 fp ON fp.user_id = t.user_id
		WHERE 
			pp.ketua_penguji_id = ? 
			OR pp.penguji_1_id = ? 
			OR pp.penguji_2_id = ?
	`

	rows, err := db.Query(query, dosenIDInt, dosenIDInt, dosenIDInt)
	if err != nil {
		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TarunaData struct {
		UserID            int    `json:"user_id"`
		NamaLengkap       string `json:"nama_lengkap"`
		TopikPenelitian   string `json:"topik_penelitian"`
		FinalLaporan100ID int    `json:"final_laporan100_id"`
	}

	var tarunaList []TarunaData
	for rows.Next() {
		var t TarunaData
		err := rows.Scan(&t.UserID, &t.NamaLengkap, &t.TopikPenelitian, &t.FinalLaporan100ID)
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

// PenilaianLaporan100Handler menangani request untuk menyimpan penilaian laporan100 (multi-file untuk penilaian)
func PenilaianLaporan100Handler(w http.ResponseWriter, r *http.Request) {
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
	finalLaporan100ID := r.FormValue("final_laporan100_id")

	if userID == "" || dosenID == "" || finalLaporan100ID == "" {
		sendError("user_id, dosen_id, dan final_laporan100_id harus diisi", http.StatusBadRequest)
		return
	}

	// ====================== TIDAK DIUBAH: Upload Catatan Perbaikan (single file) ======================
	catatanperbaikanFile, catatanperbaikanHeader, err := r.FormFile("catatanperbaikan_file")
	if err != nil {
		sendError("Gagal mengambil file Catatan Perbaikan: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer catatanperbaikanFile.Close()

	if err := filemanager.ValidateFileType(catatanperbaikanFile, catatanperbaikanHeader.Filename); err != nil {
		sendError(err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = catatanperbaikanFile.Seek(0, 0)

	catatanperbaikanFilename := fmt.Sprintf(
		"Catatan_Perbaikan_%s_%s_%s",
		userID,
		time.Now().Format("20060102150405"),
		filemanager.ValidateFileName(catatanperbaikanHeader.Filename),
	)

	catatanperbaikanPath, err := filemanager.SaveUploadedFile(
		catatanperbaikanFile,
		catatanperbaikanHeader,
		"uploads/catatanperbaikan_laporan100",
		catatanperbaikanFilename,
	)
	if err != nil {
		sendError("Gagal menyimpan file catatan perbaikan: "+err.Error(), http.StatusInternalServerError)
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
		_ = os.Remove(catatanperbaikanPath)
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
			_ = os.Remove(catatanperbaikanPath)
			for _, p := range savedFiles {
				_ = os.Remove(p)
			}
			sendError(fmt.Sprintf("Ukuran file '%s' melebihi 15MB", hdr.Filename), http.StatusBadRequest)
			return
		}

		// Validasi ekstensi (tanpa filemanager)
		ext := strings.ToLower(filepath.Ext(hdr.Filename))
		if !allowedExt[ext] {
			_ = os.Remove(catatanperbaikanPath)
			for _, p := range savedFiles {
				_ = os.Remove(p)
			}
			sendError(fmt.Sprintf("Tipe file tidak didukung untuk '%s'. Hanya pdf, doc, docx, xls, xlsx.", hdr.Filename), http.StatusBadRequest)
			return
		}

		// Buka file
		f, err := hdr.Open()
		if err != nil {
			_ = os.Remove(catatanperbaikanPath)
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
			"uploads/file_penilaian_laporan100",
			penilaianFilename,
		)
		f.Close()
		if err != nil {
			_ = os.Remove(catatanperbaikanPath)
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
		_ = os.Remove(catatanperbaikanPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal menyiapkan data file penilaian: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ====================== Database ======================
	db, err := config.GetDB()
	if err != nil {
		_ = os.Remove(catatanperbaikanPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Koneksi database gagal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		_ = os.Remove(catatanperbaikanPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal memulai transaksi: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var exists bool
	err = tx.QueryRow(`SELECT EXISTS(
		SELECT 1 FROM seminar_laporan100_penilaian 
		WHERE user_id = ? AND dosen_id = ? AND final_laporan100_id = ?
	)`, userID, dosenID, finalLaporan100ID).Scan(&exists)
	if err != nil {
		tx.Rollback()
		_ = os.Remove(catatanperbaikanPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal cek data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		_, err = tx.Exec(`UPDATE seminar_laporan100_penilaian 
			SET file_catatanperbaikan_path = ?, file_penilaian_path = ?, 
				submitted_at = NOW(), status_pengumpulan = 'sudah' 
			WHERE user_id = ? AND dosen_id = ? AND final_laporan100_id = ?`,
			catatanperbaikanPath, string(penilaianPathsJSON), userID, dosenID, finalLaporan100ID)
	} else {
		_, err = tx.Exec(`INSERT INTO seminar_laporan100_penilaian (
			user_id, final_laporan100_id, dosen_id,
			file_catatanperbaikan_path, file_penilaian_path,
			status_pengumpulan, submitted_at
		) VALUES (?, ?, ?, ?, ?, 'sudah', NOW())`,
			userID, finalLaporan100ID, dosenID, catatanperbaikanPath, string(penilaianPathsJSON))
	}
	if err != nil {
		tx.Rollback()
		_ = os.Remove(catatanperbaikanPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal menyimpan data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		_ = os.Remove(catatanperbaikanPath)
		for _, p := range savedFiles {
			_ = os.Remove(p)
		}
		sendError("Gagal commit data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Penilaian laporan 100% berhasil disimpan",
		"data": map[string]interface{}{
			"catatanperbaikan_path": catatanperbaikanPath,
			"penilaian_paths":       penilaianPaths, // kirim array agar mudah dipakai di frontend
		},
	})
}

// DownloadFilePenilaianLaporan100Handler digunakan untuk mengunduh file Catatan Perbaikan atau Penilaian Lainnya Laporan100
func DownloadFilePenilaianLaporan100Handler(w http.ResponseWriter, r *http.Request) {
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
	case strings.HasPrefix(fileName, "Catatan_Perbaikan_"):
		// (TETAP) dipakai oleh taruna untuk unduh catatan perbaikan
		baseDir = "uploads/catatanperbaikan_laporan100"

	case strings.HasPrefix(fileName, "File_Penilaian_"):
		// (DISESUAIKAN) lokasi multi-file penilaian sesuai handler upload
		baseDir = "uploads/file_penilaian_laporan100"

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
func saveLaporan100(src io.Reader, destPath string) error {
	dst, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func GetMonitoringPenilaianLaporan100Handler(w http.ResponseWriter, r *http.Request) {
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
			fp.id AS final_laporan100_id,
			u.nama_lengkap AS nama_taruna,
			t.jurusan,
			fp.topik_penelitian,

			d_ketua.nama_lengkap AS ketua_penguji,
			d1.nama_lengkap AS penguji1,
			d2.nama_lengkap AS penguji2,

			-- Hitung kelengkapan berkas
			CASE
				WHEN COUNT(
					CASE
						WHEN spp.file_catatanperbaikan_path IS NOT NULL
						AND spp.file_catatanperbaikan_path <> ''
						AND spp.file_penilaian_path IS NOT NULL
						AND spp.file_penilaian_path <> ''
						AND spp.file_penilaian_path <> '[]'
						THEN 1
					END
				) = 3 THEN 'Lengkap'
				ELSE 'Belum Lengkap'
			END AS status_kelengkapan

		FROM penguji_laporan100 pp
		JOIN final_laporan100 fp ON fp.id = pp.final_laporan100_id
		JOIN users u ON u.id = pp.user_id
		JOIN taruna t ON t.user_id = u.id

		JOIN dosen d_ketua ON d_ketua.id = pp.ketua_penguji_id
		JOIN dosen d1 ON d1.id = pp.penguji_1_id
		JOIN dosen d2 ON d2.id = pp.penguji_2_id

		LEFT JOIN seminar_laporan100_penilaian spp
			ON spp.final_laporan100_id = pp.final_laporan100_id

		GROUP BY
			fp.id, u.nama_lengkap, t.jurusan, fp.topik_penelitian,
			d_ketua.nama_lengkap, d1.nama_lengkap, d2.nama_lengkap
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
		FinalLaporan100ID int    `json:"final_laporan100_id"`
		NamaTaruna        string `json:"nama_taruna"`
		Jurusan           string `json:"jurusan"`
		TopikPenelitian   string `json:"topik_penelitian"`
		KetuaPenguji      string `json:"ketua_penguji"`
		Penguji1          string `json:"penguji1"`
		Penguji2          string `json:"penguji2"`
		StatusKelengkapan string `json:"status_kelengkapan"`
	}

	var result []MonitoringData
	for rows.Next() {
		var m MonitoringData
		err := rows.Scan(
			&m.FinalLaporan100ID,
			&m.NamaTaruna,
			&m.Jurusan,
			&m.TopikPenelitian,
			&m.KetuaPenguji,
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

func GetFinalLaporan100DetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	finalLaporan100ID := vars["id"]
	if finalLaporan100ID == "" {
		http.Error(w, "Final Laporan100 ID is required", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// --- Ambil info laporan100 + taruna ---
	queryLaporan100 := `
		SELECT fp.id, u.nama_lengkap, u.jurusan, u.kelas, fp.topik_penelitian
		FROM final_laporan100 fp
		JOIN users u ON u.id = fp.user_id
		WHERE fp.id = ?
	`
	var (
		idLaporan100    int
		namaTaruna      string
		jurusan         string
		kelas           string
		topikPenelitian string
	)
	err = db.QueryRow(queryLaporan100, finalLaporan100ID).Scan(&idLaporan100, &namaTaruna, &jurusan, &kelas, &topikPenelitian)
	if err != nil {
		http.Error(w, "Laporan100 tidak ditemukan: "+err.Error(), http.StatusNotFound)
		return
	}

	// --- Ambil id para penguji ---
	queryPenguji := `
		SELECT ketua_penguji_id, penguji_1_id, penguji_2_id
		FROM penguji_laporan100
		WHERE final_laporan100_id = ?
		LIMIT 1
	`
	var ketuaID, penguji1ID, penguji2ID int
	err = db.QueryRow(queryPenguji, finalLaporan100ID).Scan(&ketuaID, &penguji1ID, &penguji2ID)
	if err != nil {
		http.Error(w, "Data penguji tidak ditemukan: "+err.Error(), http.StatusNotFound)
		return
	}

	type PenilaianDetail struct {
		NamaDosen            string   `json:"nama_dosen"`
		StatusPengumpulan    string   `json:"status_pengumpulan"`
		FileCatatanPerbaikan string   `json:"file_catatanperbaikan"`
		PenilaianPaths       []string `json:"penilaian_paths"` // hasil parse JSON
	}

	// Ambil nama dosen
	getNamaDosen := func(dosenID int) string {
		var nama string
		if err := db.QueryRow(`SELECT nama_lengkap FROM dosen WHERE id = ?`, dosenID).Scan(&nama); err != nil {
			return "-"
		}
		return nama
	}

	// Ambil detail penilaian per dosen (file_penilaian_path = JSON string pada kolom TEXT)
	getPenilaian := func(dosenID int) PenilaianDetail {
		namaDosen := getNamaDosen(dosenID)

		var (
			status                 sql.NullString
			fileCatatanPerbaikanNS sql.NullString
			filePenilaianNS        sql.NullString
		)

		err := db.QueryRow(`
			SELECT status_pengumpulan, file_catatanperbaikan_path, file_penilaian_path
			FROM seminar_laporan100_penilaian
			WHERE final_laporan100_id = ? AND dosen_id = ?
			LIMIT 1
		`, finalLaporan100ID, dosenID).Scan(&status, &fileCatatanPerbaikanNS, &filePenilaianNS)

		// Default jika belum ada record
		if err != nil {
			return PenilaianDetail{
				NamaDosen:            namaDosen,
				StatusPengumpulan:    "belum",
				FileCatatanPerbaikan: "",
				PenilaianPaths:       []string{},
			}
		}

		// Parse JSON array dari kolom TEXT; fallback: jika bukan JSON tapi ada string non-kosong, jadikan single item
		var paths []string
		if filePenilaianNS.Valid && strings.TrimSpace(filePenilaianNS.String) != "" && strings.TrimSpace(filePenilaianNS.String) != "[]" {
			if err := json.Unmarshal([]byte(filePenilaianNS.String), &paths); err != nil {
				// fallback: treat as single path string
				paths = []string{filePenilaianNS.String}
			}
		} else {
			paths = []string{}
		}

		return PenilaianDetail{
			NamaDosen:            namaDosen,
			StatusPengumpulan:    ternaryLaporan100(status.Valid && status.String != "", status.String, "belum"),
			FileCatatanPerbaikan: ternaryLaporan100(fileCatatanPerbaikanNS.Valid, fileCatatanPerbaikanNS.String, ""),
			PenilaianPaths:       paths,
		}
	}

	resp := map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"nama_taruna":      namaTaruna,
			"jurusan":          jurusan,
			"kelas":            kelas,
			"topik_penelitian": topikPenelitian,
			"ketua_penguji":    getPenilaian(ketuaID),
			"penguji1":         getPenilaian(penguji1ID),
			"penguji2":         getPenilaian(penguji2ID),
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// helper kecil biar rapi (ternaryLaporan100-like)
func ternaryLaporan100[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

// Helper function untuk mendapatkan data penilaian dosen
func getPengujiLaporan100Data(db *sql.DB, laporan100ID string, dosenID int) map[string]interface{} {
	query := `
		SELECT 
			d.nama_lengkap,
			spp.file_penilaian_path,
			spp.file_berita_acara_path,
			spp.status_pengumpulan
		FROM dosen d
		LEFT JOIN seminar_laporan100_penilaian spp ON spp.dosen_id = d.id 
			AND spp.seminar_laporan100_id = ?
		WHERE d.id = ?
	`

	var data struct {
		NamaLengkap       string
		FilePenilaianPath sql.NullString
		BeritaAcaraPath   sql.NullString
		StatusPengumpulan sql.NullString
	}

	err := db.QueryRow(query, laporan100ID, dosenID).Scan(
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

func GetCatatanPerbaikanTarunaLaporan100Handler(w http.ResponseWriter, r *http.Request) {
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

	// Query ambil catatan perbaikan
	query := `
		SELECT spp.id, d.nama_lengkap, fp.topik_penelitian, spp.file_catatanperbaikan_path, spp.submitted_at
		FROM seminar_laporan100_penilaian spp
		JOIN dosen d ON spp.dosen_id = d.id
		LEFT JOIN final_laporan100 fp ON spp.final_laporan100_id = fp.id
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

	var results []CatatanPerbaikan
	for rows.Next() {
		var c CatatanPerbaikan
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
