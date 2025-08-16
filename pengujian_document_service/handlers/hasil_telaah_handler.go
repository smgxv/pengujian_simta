package handlers

import (
	"database/sql"
	"document_service/config"
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

// Struktur untuk response hasil telaah
type HasilTelaahResponse struct {
	ID              int       `json:"id"`
	NamaDosen       string    `json:"nama_dosen"`
	TopikPenelitian string    `json:"topik_penelitian"`
	FilePath        string    `json:"file_path"`
	TanggalTelaah   time.Time `json:"tanggal_telaah"`
	JumlahTelaah    int       `json:"jumlah_telaah"`
	StatusTelaah    string    `json:"status_telaah"`
}

// UploadHasilTelaahHandler digunakan untuk mengunggah file hasil telaah ICP
func UploadHasilTelaahHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
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

	// Parse multipart form
	err := r.ParseMultipartForm(filemanager.MaxFileSize)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
		})
		return
	}

	// Get form values
	userID := r.FormValue("user_id")
	dosenID := r.FormValue("dosen_id")
	topikPenelitian := r.FormValue("topik_penelitian")

	if userID == "" || dosenID == "" || topikPenelitian == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Missing required fields",
		})
		return
	}

	// Connect to database for getting icp_id
	db, err := config.GetDB()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Database error: " + err.Error(),
		})
		return
	}
	defer db.Close()

	// Get icp_id from final_icp table
	var icpID int
	err = db.QueryRow("SELECT id FROM final_icp WHERE user_id = ? AND topik_penelitian = ?", userID, topikPenelitian).Scan(&icpID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "ICP tidak ditemukan: " + err.Error(),
		})
		return
	}

	// Handle file upload
	file, handler, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal mengambil file: " + err.Error(),
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
	file.Seek(0, 0)

	// Sanitize filename and generate final name
	safeFilename := filemanager.ValidateFileName(handler.Filename)
	filename := fmt.Sprintf("HASIL_TELAAH_ICP_%s_%s_%s_%s",
		userID,
		dosenID,
		time.Now().Format("20060102150405"),
		safeFilename)
	uploadDir := "uploads/hasil_telaah_icp"

	// Save securely
	filePath, err := filemanager.SaveUploadedFile(file, handler, uploadDir, filename)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	// Insert into database
	query := `INSERT INTO hasil_telaah_icp (icp_id, dosen_id, user_id, topik_penelitian, file_path, tanggal_telaah) 
			  VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	result, err := db.Exec(query, icpID, dosenID, userID, topikPenelitian, filePath)
	if err != nil {
		os.Remove(filePath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Gagal menyimpan ke database: " + err.Error(),
		})
		return
	}

	// Get inserted ID
	id, _ := result.LastInsertId()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Hasil telaah berhasil diunggah",
		"data": map[string]interface{}{
			"id":        id,
			"file_path": filePath,
		},
	})
}

// DownloadFileHasilTelaahICPHandler digunakan untuk mengunduh hasil telaah ICP
func DownloadFileHasilTelaahICPHandler(w http.ResponseWriter, r *http.Request) {
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

	fileName := filepath.Base(rawPath) // Mencegah path traversal

	// Tentukan direktori berdasarkan jenis file
	var baseDir string
	if strings.HasPrefix(fileName, "HASIL_TELAAH_ICP_") {
		baseDir = "uploads/hasil_telaah_icp"
	} else {
		http.Error(w, "Prefix nama file tidak valid", http.StatusForbidden)
		return
	}

	// Bangun path absolut
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
	file, err := os.Open(absPath)
	if err != nil {
		http.Error(w, "File tidak ditemukan", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Set header untuk download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/pdf")

	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Gagal mengirim file", http.StatusInternalServerError)
		return
	}
}

func GetHasilTelaahTarunaHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Ambil user_id dari query parameter & sanitasi
	userID := r.URL.Query().Get("user_id")
	sanitizedUserID := utils.SanitizeLogInput(userID)
	fmt.Printf("[Debug] Received request for user_id: %s\n", sanitizedUserID)

	if userID == "" {
		utils.RespondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status":  "error",
			"message": "User ID is required",
		})
		return
	}

	// Ambil koneksi DB
	db, err := config.GetDB()
	if err != nil {
		fmt.Printf("[Error] Database connection error: %v\n", err)
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": "Database error: " + err.Error(),
		})
		return
	}
	defer db.Close()

	fmt.Printf("[Debug] Preparing query for user_id: %s\n", sanitizedUserID)

	// Query
	query := `
		SELECT ht.id, d.nama_lengkap, ht.topik_penelitian, ht.file_path, ht.tanggal_telaah
		FROM hasil_telaah_icp ht
		JOIN dosen d ON ht.dosen_id = d.id
		WHERE ht.user_id = ?
		ORDER BY ht.tanggal_telaah DESC`

	rows, err := db.Query(query, userID)
	if err != nil {
		fmt.Printf("[Error] Query execution error: %v\n", err)
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"status":  "error",
			"message": "Query error: " + err.Error(),
		})
		return
	}
	defer rows.Close()

	var results []HasilTelaahResponse
	for rows.Next() {
		var result HasilTelaahResponse
		err := rows.Scan(
			&result.ID,
			&result.NamaDosen,
			&result.TopikPenelitian,
			&result.FilePath,
			&result.TanggalTelaah,
		)
		if err != nil {
			fmt.Printf("[Error] Row scan error: %v\n", err)
			continue
		}
		results = append(results, result)
		fmt.Printf("[Debug] Found hasil telaah: ID=%d, Dosen=%s, Topik=%s\n",
			result.ID, result.NamaDosen, result.TopikPenelitian)
	}

	fmt.Printf("[Debug] Found %d hasil telaah records for user_id: %s\n", len(results), sanitizedUserID)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"data":   results,
	})
}

func GetMonitoringTelaahHandler(w http.ResponseWriter, r *http.Request) {
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
			fi.id AS final_icp_id,
			u.nama_lengkap AS nama_taruna,
			fi.jurusan,
			fi.kelas,
			fi.topik_penelitian,

			d1.nama_lengkap AS penelaah_1,
			d2.nama_lengkap AS penelaah_2,

			COUNT(ht.id) AS jumlah_telaah,
			fi.status AS status_icp

		FROM final_icp fi
		JOIN users u ON u.id = fi.user_id
		JOIN penelaah_icp pi ON pi.final_icp_id = fi.id
		LEFT JOIN dosen d1 ON d1.id = pi.penelaah_1_id
		LEFT JOIN dosen d2 ON d2.id = pi.penelaah_2_id
		LEFT JOIN hasil_telaah_icp ht ON ht.icp_id = fi.id

		GROUP BY fi.id, u.nama_lengkap, fi.jurusan, fi.kelas, fi.topik_penelitian,
		         d1.nama_lengkap, d2.nama_lengkap, fi.status
		ORDER BY u.nama_lengkap ASC
	`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Query error: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Query error",
		})
		return
	}
	defer rows.Close()

	type MonitoringData struct {
		FinalICPId        int    `json:"final_icp_id"`
		NamaTaruna        string `json:"nama_taruna"`
		Jurusan           string `json:"jurusan"`
		Kelas             string `json:"kelas"`
		TopikPenelitian   string `json:"topik_penelitian"`
		Penelaah1         string `json:"penelaah_1"`
		Penelaah2         string `json:"penelaah_2"`
		StatusKelengkapan string `json:"status_kelengkapan"`
		StatusICP         string `json:"status_icp"`
	}

	var result []MonitoringData

	for rows.Next() {
		var m MonitoringData
		var jumlahTelaah int

		err := rows.Scan(
			&m.FinalICPId,
			&m.NamaTaruna,
			&m.Jurusan,
			&m.Kelas,
			&m.TopikPenelitian,
			&m.Penelaah1,
			&m.Penelaah2,
			&jumlahTelaah,
			&m.StatusICP,
		)
		if err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}

		// Logika status kelengkapan
		switch jumlahTelaah {
		case 2:
			m.StatusKelengkapan = "✅ Lengkap"
		case 1:
			m.StatusKelengkapan = "⚠️ Kurang 1 Telaah"
		default:
			m.StatusKelengkapan = "❌ Belum Ditelaah"
		}

		result = append(result, m)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Row iteration error: %v", err)
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

// Handler untuk mendapatkan detail telaah berdasarkan final_icp_id
func GetDetailTelaahICPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Ambil parameter ?id=
	icpIDStr := r.URL.Query().Get("id")
	icpID, err := strconv.Atoi(icpIDStr)
	if err != nil || icpID <= 0 {
		http.Error(w, "ID ICP tidak valid", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Ambil info taruna dan ICP
	var info struct {
		NamaTaruna      string `json:"nama_taruna"`
		Jurusan         string `json:"jurusan"`
		Kelas           string `json:"kelas"`
		TopikPenelitian string `json:"topik_penelitian"`
		StatusICP       string `json:"status_icp"`
	}
	infoQuery := `
		SELECT u.nama_lengkap, fi.jurusan, fi.kelas, fi.topik_penelitian, fi.status
		FROM final_icp fi
		JOIN users u ON u.id = fi.user_id
		WHERE fi.id = ?
	`
	err = db.QueryRow(infoQuery, icpID).Scan(&info.NamaTaruna, &info.Jurusan, &info.Kelas, &info.TopikPenelitian, &info.StatusICP)
	if err != nil {
		http.Error(w, "ICP tidak ditemukan", http.StatusNotFound)
		return
	}

	// Ambil info penelaah dan status telaahnya
	telaahQuery := `
		SELECT d.nama_lengkap, ht.tanggal_telaah, ht.file_path
		FROM penelaah_icp p
		JOIN dosen d ON d.id = p.penelaah_1_id
		LEFT JOIN hasil_telaah_icp ht ON ht.icp_id = p.final_icp_id AND ht.dosen_id = p.penelaah_1_id
		WHERE p.final_icp_id = ?

		UNION ALL

		SELECT d.nama_lengkap, ht.tanggal_telaah, ht.file_path
		FROM penelaah_icp p
		JOIN dosen d ON d.id = p.penelaah_2_id
		LEFT JOIN hasil_telaah_icp ht ON ht.icp_id = p.final_icp_id AND ht.dosen_id = p.penelaah_2_id
		WHERE p.final_icp_id = ?
	`

	rows, err := db.Query(telaahQuery, icpID, icpID)
	if err != nil {
		http.Error(w, "Gagal mengambil data telaah", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TelaahItem struct {
		NamaDosen     string `json:"nama_dosen"`
		TanggalTelaah string `json:"tanggal_telaah"`
		FilePath      string `json:"file_path"`
	}
	var telaahList []TelaahItem
	telaahCount := 0

	for rows.Next() {
		var item TelaahItem
		var tanggal sql.NullString
		var file sql.NullString

		if err := rows.Scan(&item.NamaDosen, &tanggal, &file); err == nil {
			if tanggal.Valid {
				item.TanggalTelaah = tanggal.String
				telaahCount++
			}
			if file.Valid {
				item.FilePath = file.String
			}
			telaahList = append(telaahList, item)
		}
	}

	// Tentukan status telaah berdasarkan jumlah
	statusTelaah := "❌ Belum Ditelaah"
	if telaahCount == 2 {
		statusTelaah = "✅ Lengkap"
	} else if telaahCount == 1 {
		statusTelaah = "⚠️ Kurang 1 Telaah"
	}

	// Keluarkan JSON
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"info": map[string]interface{}{
			"nama_taruna":      info.NamaTaruna,
			"jurusan":          info.Jurusan,
			"kelas":            info.Kelas,
			"topik_penelitian": info.TopikPenelitian,
			"status_icp":       info.StatusICP,
			"status_telaah":    statusTelaah,
		},
		"telaah": telaahList,
	})
}

// Handler untuk mendapatkan daftar taruna yang ditelaah oleh dosen
func GetTarunaTopicsHandler(w http.ResponseWriter, r *http.Request) {
	// Tangani preflight CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	// w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	dosenID := r.URL.Query().Get("dosen_id")
	if dosenID == "" {
		http.Error(w, "Missing dosen_id parameter", http.StatusBadRequest)
		return
	}

	query := `
	SELECT 
		u.id AS user_id,
		u.nama_lengkap,
		fi.topik_penelitian
	FROM penelaah_icp p
	JOIN final_icp fi ON fi.id = p.final_icp_id
	JOIN users u ON u.id = fi.user_id
	WHERE p.penelaah_1_id = ? OR p.penelaah_2_id = ?
	ORDER BY u.nama_lengkap ASC;
	`

	rows, err := db.Query(query, dosenID, dosenID)
	if err != nil {
		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []struct {
		UserID          int    `json:"user_id"`
		NamaLengkap     string `json:"nama_lengkap"`
		TopikPenelitian string `json:"topik_penelitian"`
	}

	for rows.Next() {
		var row struct {
			UserID          int    `json:"user_id"`
			NamaLengkap     string `json:"nama_lengkap"`
			TopikPenelitian string `json:"topik_penelitian"`
		}
		if err := rows.Scan(&row.UserID, &row.NamaLengkap, &row.TopikPenelitian); err != nil {
			http.Error(w, "Scan error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		results = append(results, row)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   results,
	})
}

// GetFinalICPByDosenHandler menangani request untuk mendapatkan data telaah ICP berdasarkan ID dosen
func GetFinalICPByDosenHandler(w http.ResponseWriter, r *http.Request) {
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

	// Tambahkan kolom file_pendukung_path
	query := `
		SELECT fl.id, fl.user_id, fl.topik_penelitian, fl.file_path, fl.file_pendukung_path, u.nama_lengkap
		FROM final_icp fl
		JOIN users u ON fl.user_id = u.id
		JOIN penelaah_icp pl ON fl.id = pl.final_icp_id
		WHERE pl.penelaah_1_id = ? OR pl.penelaah_2_id = ?
	`

	rows, err := db.Query(query, dosenIDInt, dosenIDInt)
	if err != nil {
		http.Error(w, "Error querying database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type SupportFile struct {
		Index int    `json:"index"`
		Name  string `json:"name"`
		URL   string `json:"url"`
	}

	type FinalICPData struct {
		ID                int           `json:"id"`
		UserID            int           `json:"user_id"`
		TopikPenelitian   string        `json:"topik_penelitian"`
		FilePath          string        `json:"file_path"`
		TarunaNama        string        `json:"taruna_nama"`
		FinalDownloadURL  string        `json:"final_download_url"`
		FilePendukungPath string        `json:"file_pendukung_path"` // JSON string asli dari DB
		FilePendukungURL  []string      `json:"file_pendukung_url"`  // URL unduh per index
		SupportFiles      []SupportFile `json:"support_files"`       // dengan nama file
	}

	var finalicps []FinalICPData
	for rows.Next() {
		var (
			id, userID        int
			topik, filePath   string
			filePendukungJSON sql.NullString
			tarunaNama        string
		)
		if err := rows.Scan(&id, &userID, &topik, &filePath, &filePendukungJSON, &tarunaNama); err != nil {
			http.Error(w, "Error scanning rows: "+err.Error(), http.StatusInternalServerError)
			return
		}

		item := FinalICPData{
			ID:               id,
			UserID:           userID,
			TopikPenelitian:  topik,
			FilePath:         filePath,
			TarunaNama:       tarunaNama,
			FinalDownloadURL: fmt.Sprintf("/api/document/finalicp/download/%d?type=final", id),
		}

		// Isi field file_pendukung_path (as-is) jika ada
		if filePendukungJSON.Valid {
			item.FilePendukungPath = filePendukungJSON.String
		}

		// Bangun daftar URL + nama file
		var filePendukungURL []string
		var supportFiles []SupportFile

		if filePendukungJSON.Valid && filePendukungJSON.String != "" {
			// Bisa format lama: []string
			var arrStr []string
			if err := json.Unmarshal([]byte(filePendukungJSON.String), &arrStr); err == nil && len(arrStr) > 0 {
				for i, p := range arrStr {
					url := fmt.Sprintf("/api/document/finalicp/download/%d?type=support&index=%d", id, i)
					filePendukungURL = append(filePendukungURL, url)
					name := filepath.Base(p)
					supportFiles = append(supportFiles, SupportFile{Index: i, Name: name, URL: url})
				}
			} else {
				// Bisa format baru: []{original, stored}
				var arrObj []struct {
					Original string `json:"original"`
					Stored   string `json:"stored"`
				}
				if err := json.Unmarshal([]byte(filePendukungJSON.String), &arrObj); err == nil && len(arrObj) > 0 {
					for i, o := range arrObj {
						url := fmt.Sprintf("/api/document/finalicp/download/%d?type=support&index=%d", id, i)
						filePendukungURL = append(filePendukungURL, url)
						name := o.Original
						if name == "" {
							name = filepath.Base(o.Stored)
						}
						supportFiles = append(supportFiles, SupportFile{Index: i, Name: name, URL: url})
					}
				}
			}
		}

		item.FilePendukungURL = filePendukungURL
		item.SupportFiles = supportFiles
		finalicps = append(finalicps, item)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Row iteration error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   finalicps,
	})
}
