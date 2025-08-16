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
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Handler untuk mengupload final proposal + form bimbingan + file pendukung (wajib ≥1)
func UploadFinalProposalHandler(w http.ResponseWriter, r *http.Request) {
	// ===== CORS =====
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// ===== Batas total payload (opsional): 15MB * 4 = 60MB =====
	if r.ContentLength > filemanager.MaxFileSize*4 {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Total file terlalu besar. Maksimal 60MB",
		})
		return
	}

	// ===== Parse multipart form =====
	if err := r.ParseMultipartForm(filemanager.MaxFileSize * 4); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Form terlalu besar atau rusak: " + err.Error(),
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

	if userID == "" || namaLengkap == "" || topikPenelitian == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	userIDInt := utils.ParseInt(userID)

	// ===== Validasi tipe/ukuran =====
	const maxSize = int64(15 * 1024 * 1024) // 15MB
	allowedFinalExt := map[string]bool{".pdf": true}
	allowedSupportExt := map[string]bool{
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	}
	hasAllowedExt := func(name string, allowed map[string]bool) bool {
		ext := strings.ToLower(filepath.Ext(name))
		return allowed[ext]
	}

	// Untuk cleanup massal bila ada error di tengah jalan
	var savedPaths []string
	cleanup := func() {
		for _, p := range savedPaths {
			_ = os.Remove(p)
		}
	}

	// ===== FINAL PROPOSAL (wajib, PDF) =====
	finalFile, finalHeader, err := r.FormFile("final_proposal_file")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Gagal mengambil file Final Proposal: " + err.Error(),
		})
		return
	}
	defer finalFile.Close()

	if finalHeader.Size > maxSize {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Ukuran Final Proposal melebihi 15MB",
		})
		return
	}
	if !hasAllowedExt(finalHeader.Filename, allowedFinalExt) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Tipe Final Proposal tidak diizinkan (hanya PDF)",
		})
		return
	}
	if err := filemanager.ValidateFileType(finalFile, finalHeader.Filename); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	_, _ = finalFile.Seek(0, 0)

	finalFilename := fmt.Sprintf("FINAL_PROPOSAL_%s_%s_%s",
		userID,
		time.Now().Format("20060102150405"),
		filemanager.ValidateFileName(finalHeader.Filename))
	finalFilePath, err := filemanager.SaveUploadedFile(finalFile, finalHeader, "uploads/finalproposal", finalFilename)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	savedPaths = append(savedPaths, finalFilePath)

	// ===== FORM BIMBINGAN (wajib, PDF) =====
	formFile, formHeader, err := r.FormFile("form_bimbingan_file")
	if err != nil {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Gagal mengambil file Form Bimbingan: " + err.Error(),
		})
		return
	}
	defer formFile.Close()

	if formHeader.Size > maxSize {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Ukuran Form Bimbingan melebihi 15MB",
		})
		return
	}
	if !hasAllowedExt(formHeader.Filename, allowedFinalExt) {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Tipe Form Bimbingan tidak diizinkan (hanya PDF)",
		})
		return
	}
	if err := filemanager.ValidateFileType(formFile, formHeader.Filename); err != nil {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	_, _ = formFile.Seek(0, 0)

	formFilename := fmt.Sprintf("FORM_BIMBINGAN_%s_%s_%s",
		userID,
		time.Now().Format("20060102150405"),
		filemanager.ValidateFileName(formHeader.Filename))
	formFilePath, err := filemanager.SaveUploadedFile(formFile, formHeader, "uploads/finalproposal", formFilename)
	if err != nil {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	savedPaths = append(savedPaths, formFilePath)

	// ===== FILE PENDUKUNG (wajib ≥1) =====
	supportFiles := r.MultipartForm.File["support_files[]"]
	if len(supportFiles) == 0 {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Minimal 1 file pendukung wajib diunggah",
		})
		return
	}

	var supportPaths []string
	supportDir := "uploads/pendukungproposal"
	for _, fh := range supportFiles {
		f, err := fh.Open()
		if err != nil {
			cleanup()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": "Gagal membuka file pendukung: " + err.Error(),
			})
			return
		}

		if fh.Size > maxSize {
			f.Close()
			cleanup()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": fmt.Sprintf("Ukuran file pendukung melebihi 15MB (%s)", fh.Filename),
			})
			return
		}
		if !hasAllowedExt(fh.Filename, allowedSupportExt) {
			f.Close()
			cleanup()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "error",
				"message": fmt.Sprintf("Tipe file pendukung tidak diizinkan (%s). Hanya PDF, DOC, DOCX, XLS, XLSX.", fh.Filename),
			})
			return
		}

		_, _ = f.Seek(0, 0)
		safeName := filemanager.ValidateFileName(fh.Filename)
		supportName := fmt.Sprintf("%d_%s", time.Now().Unix(), safeName)

		outPath, err := filemanager.SaveUploadedFile(f, fh, supportDir, supportName)
		f.Close()
		if err != nil {
			cleanup()
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
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Gagal koneksi database: " + err.Error(),
		})
		return
	}
	defer db.Close()

	finalProposalModel := models.NewFinalProposalModel(db)
	finalProposal := &entities.FinalProposal{
		UserID:            userIDInt,
		NamaLengkap:       namaLengkap,
		Jurusan:           jurusan,
		Kelas:             kelas,
		TopikPenelitian:   topikPenelitian,
		FilePath:          finalFilePath,
		FormBimbinganPath: formFilePath,
		Keterangan:        keterangan,
	}
	// Simpan JSON array path pendukung ke kolom TEXT file_pendukung_path
	if err := finalProposal.SetProposalSupportingFiles(supportPaths); err != nil {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Gagal encode file pendukung: " + err.Error(),
		})
		return
	}

	if err := finalProposalModel.Create(finalProposal); err != nil {
		cleanup()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "error",
			"message": "Gagal menyimpan ke database: " + err.Error(),
		})
		return
	}

	// ===== RESPONSE =====
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"message": "Final Proposal dan file pendukung berhasil diunggah",
		"data": map[string]any{
			"id":                  finalProposal.ID,
			"file_path":           finalFilePath,
			"form_bimbingan_path": formFilePath,
			"file_pendukung_path": supportPaths, // kirim array untuk kemudahan klien
		},
	})
}

func respondJSON(w http.ResponseWriter, code int, payload any) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

// Handler untuk mengambil daftar final proposal berdasarkan user_id (lengkap dengan URL download)
func GetFinalProposalHandler(w http.ResponseWriter, r *http.Request) {
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

	finalProposalModel := models.NewFinalProposalModel(db)
	finalProposals, err := finalProposalModel.GetByUserID(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mapped := []map[string]interface{}{}
	for _, p := range finalProposals {
		// Parse daftar path pendukung dari kolom JSON (aman jika kosong/invalid)
		var supportPaths []string
		if s := strings.TrimSpace(p.FilePendukungPath); s != "" {
			_ = json.Unmarshal([]byte(s), &supportPaths) // kalau gagal, biarkan kosong
		}

		// Buat URL download per index
		filePendukungURL := make([]string, 0, len(supportPaths))
		supportFiles := make([]map[string]interface{}, 0, len(supportPaths))
		for i, sp := range supportPaths {
			url := fmt.Sprintf("/api/document/finalproposal/download/%d?type=support&index=%d", p.ID, i)
			filePendukungURL = append(filePendukungURL, url)
			supportFiles = append(supportFiles, map[string]interface{}{
				"index": i,
				"name":  filepath.Base(sp),
				"url":   url,
			})
		}

		finalURL := fmt.Sprintf("/api/document/finalproposal/download/%d?type=final", p.ID)
		formURL := fmt.Sprintf("/api/document/finalproposal/download/%d?type=form", p.ID)

		mapped = append(mapped, map[string]interface{}{
			"taruna_id":        p.UserID,
			"nama_lengkap":     p.NamaLengkap,
			"jurusan":          p.Jurusan,
			"kelas":            p.Kelas,
			"topik_penelitian": p.TopikPenelitian,
			"status":           p.Status,

			"final_proposal_id":   p.ID,     // penting untuk download by id
			"final_download_url":  finalURL, // file final proposal
			"form_bimbingan_path": p.FormBimbinganPath,
			"form_bimbingan_url":  formURL, // file form bimbingan

			"file_pendukung_path": p.FilePendukungPath, // raw JSON dari DB
			"file_pendukung_url":  filePendukungURL,    // array URL download
			"support_files":       supportFiles,        // array objek {index,name,url}

			"created_at": p.CreatedAt,
			"updated_at": p.UpdatedAt,
		})
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   mapped,
	})
}

// Handler untuk mengambil data gabungan taruna dan final proposal (beserta file pendukung)
func GetAllFinalProposalWithTarunaHandler(w http.ResponseWriter, r *http.Request) {
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

	// Tambahkan kolom file_pendukung_path dari tabel final_proposal
	query := `
		SELECT 
			t.user_id AS taruna_id,
			t.nama_lengkap,
			t.jurusan,
			t.kelas,
			COALESCE(f.topik_penelitian, '') AS topik_penelitian,
			COALESCE(f.status, '') AS status,
			COALESCE(f.id, 0) AS final_proposal_id,
			COALESCE(f.file_pendukung_path, '[]') AS file_pendukung_path
		FROM taruna t
		LEFT JOIN final_proposal f ON t.user_id = f.user_id
		ORDER BY t.nama_lengkap ASC
	`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type TarunaProposal struct {
		TarunaID         int    `json:"taruna_id"`
		NamaLengkap      string `json:"nama_lengkap"`
		Jurusan          string `json:"jurusan"`
		Kelas            string `json:"kelas"`
		TopikPenelitian  string `json:"topik_penelitian"`
		Status           string `json:"status"`
		FinalProposalID  int    `json:"final_proposal_id"`
		FilePendukungRaw string `json:"file_pendukung_path"` // JSON string: ["path1","path2",...]
	}

	var results []TarunaProposal
	for rows.Next() {
		var data TarunaProposal
		if err := rows.Scan(
			&data.TarunaID,
			&data.NamaLengkap,
			&data.Jurusan,
			&data.Kelas,
			&data.TopikPenelitian,
			&data.Status,
			&data.FinalProposalID,
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

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   results,
	})
}

// Handler untuk update status Final Proposal
func UpdateFinalProposalStatusHandler(w http.ResponseWriter, r *http.Request) {
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

	query := "UPDATE final_proposal SET status = ? WHERE id = ?"
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

// Handler untuk download file Final Proposal, Form Bimbingan, atau File Pendukung
func DownloadFinalProposalHandler(w http.ResponseWriter, r *http.Request) {
	// ===== CORS =====
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// ===== Param =====
	vars := mux.Vars(r)
	proposalID := vars["id"]                 // /download/{id}
	fileType := r.URL.Query().Get("type")    // "final" | "form" | "support"
	supportIdx := r.URL.Query().Get("index") // index untuk file pendukung

	if fileType == "" {
		fileType = "final"
	}

	// ===== DB =====
	db, err := config.GetDB()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var filePath string

	switch fileType {
	case "final":
		// Ambil path file final proposal
		err = db.QueryRow("SELECT file_path FROM final_proposal WHERE id = ?", proposalID).Scan(&filePath)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "File not found", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

	case "form":
		// Ambil path form bimbingan
		err = db.QueryRow("SELECT form_bimbingan_path FROM final_proposal WHERE id = ?", proposalID).Scan(&filePath)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "File not found", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

	case "support":
		// Ambil JSON array file pendukung
		var supportJSON string
		err = db.QueryRow("SELECT file_pendukung_path FROM final_proposal WHERE id = ?", proposalID).Scan(&supportJSON)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "File pendukung tidak ditemukan", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		var paths []string
		if err := json.Unmarshal([]byte(supportJSON), &paths); err != nil {
			http.Error(w, "Gagal membaca data file pendukung", http.StatusInternalServerError)
			return
		}

		idx, err := strconv.Atoi(supportIdx)
		if err != nil || idx < 0 || idx >= len(paths) {
			http.Error(w, "Index file pendukung tidak valid", http.StatusBadRequest)
			return
		}

		filePath = paths[idx]

	default:
		http.Error(w, "type tidak valid. Gunakan 'final', 'form', atau 'support'", http.StatusBadRequest)
		return
	}

	// ===== Validasi file di disk =====
	if stat, err := os.Stat(filePath); err != nil || stat.IsDir() {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// ===== Header download =====
	fileName := filepath.Base(filePath)
	ctype := mime.TypeByExtension(strings.ToLower(filepath.Ext(fileName)))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	w.Header().Set("Content-Type", ctype)

	// ===== Kirim file =====
	http.ServeFile(w, r, filePath)
}

// Handler untuk download file Final Proposal pada dosen
func DownloadFinalProposalDosenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	proposalID := vars["id"] // /finalproposal/dosen/download/{id}
	if proposalID == "" {
		http.Error(w, "Parameter 'id' wajib disediakan", http.StatusBadRequest)
		return
	}

	// Ambil parameter type (default = proposal)
	fileType := r.URL.Query().Get("type")
	if fileType == "" {
		fileType = "proposal"
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var filePath string

	if fileType == "proposal" {
		// Ambil path file final proposal utama
		err = db.QueryRow(`SELECT file_path FROM final_proposal WHERE id = ?`, proposalID).Scan(&filePath)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "File tidak ditemukan", http.StatusNotFound)
			} else {
				http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
	} else if fileType == "support" {
		// Ambil file pendukung
		var raw string
		err = db.QueryRow(`SELECT file_pendukung_path FROM final_proposal WHERE id = ?`, proposalID).Scan(&raw)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Data tidak ditemukan", http.StatusNotFound)
			} else {
				http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if raw == "" {
			http.Error(w, "Tidak ada file pendukung", http.StatusNotFound)
			return
		}

		// Parsing JSON array path
		var paths []string
		if err := json.Unmarshal([]byte(raw), &paths); err != nil {
			http.Error(w, "Format file pendukung tidak valid", http.StatusInternalServerError)
			return
		}

		// Ambil index dari query
		indexStr := r.URL.Query().Get("index")
		if indexStr == "" {
			http.Error(w, "Parameter 'index' wajib untuk file pendukung", http.StatusBadRequest)
			return
		}
		idx, err := strconv.Atoi(indexStr)
		if err != nil || idx < 0 || idx >= len(paths) {
			http.Error(w, "Index file pendukung tidak valid", http.StatusBadRequest)
			return
		}

		filePath = paths[idx]
	} else {
		http.Error(w, "Tipe file tidak valid", http.StatusBadRequest)
		return
	}

	// Kirim file ke client
	fileName := filepath.Base(filePath)
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filePath)
}
