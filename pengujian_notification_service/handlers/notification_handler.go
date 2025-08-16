package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"notification_service/config"
	"notification_service/models"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func BroadcastNotification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	// Max 20MB file
	err := r.ParseMultipartForm(20 << 20)
	if err != nil {
		http.Error(w, "Gagal parsing form data", http.StatusBadRequest)
		return
	}

	judul := r.FormValue("judul")
	deskripsi := r.FormValue("deskripsi")
	targets := r.Form["target"] // checkbox → array
	files := r.MultipartForm.File["files"]

	var fileURLs []string
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			http.Error(w, "Gagal membuka file", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		ext := filepath.Ext(fileHeader.Filename)
		nameOnly := strings.TrimSuffix(fileHeader.Filename, ext)
		timestamp := time.Now().Format("20060102_150405")
		fileName := fmt.Sprintf("%s_%s%s", nameOnly, timestamp, ext)

		path := "./uploads/" + fileName

		dst, err := os.Create(path)
		if err != nil {
			http.Error(w, "Gagal menyimpan file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		io.Copy(dst, file)
		fileURLs = append(fileURLs, "/uploads/"+fileName)
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Validasi fallback deskripsi
	if deskripsi == "" {
		deskripsi = "-"
	}

	// Hilangkan target duplikat
	uniqueTargetMap := map[string]bool{}
	var filteredTargets []string
	for _, t := range targets {
		if !uniqueTargetMap[t] {
			uniqueTargetMap[t] = true
			filteredTargets = append(filteredTargets, t)
		}
	}

	notif := models.Notification{
		Judul:     judul,
		Deskripsi: deskripsi,
		Target:    strings.Join(filteredTargets, ","),
		CreatedAt: time.Now(),
	}

	// Masukkan fileURLs yang telah dikumpulkan
	if len(fileURLs) > 0 {
		fileJSON, _ := json.Marshal(fileURLs)
		notif.FileURLs = string(fileJSON)
	}

	query := `INSERT INTO notifications (judul, deskripsi, target, file_urls, created_at) VALUES (?, ?, ?, ?, ?)`
	res, err := db.Exec(query, notif.Judul, notif.Deskripsi, notif.Target, notif.FileURLs, notif.CreatedAt)

	if err != nil {
		log.Printf("❌ INSERT error: %+v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Ambil ID hasil insert
	insertedID, _ := res.LastInsertId()

	// Kirim response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Notifikasi berhasil dikirim",
		"id":      insertedID,
	})

}

func GetNotifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Ambil role dari query parameter
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "Taruna" // default fallback
	}

	rows, err := db.Query("SELECT id, judul, deskripsi, target, file_urls, created_at FROM notifications ORDER BY created_at DESC LIMIT 10")
	if err != nil {
		http.Error(w, "Query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []models.Notification

	for rows.Next() {
		var n models.Notification
		err := rows.Scan(&n.ID, &n.Judul, &n.Deskripsi, &n.Target, &n.FileURLs, &n.CreatedAt)
		if err != nil {
			continue
		}
		// Filter sesuai role
		if strings.Contains(n.Target, role) {
			results = append(results, n)
		}
	}

	json.NewEncoder(w).Encode(results)
}

func GetNotificationByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	id := vars["id"]
	role := r.URL.Query().Get("role") // Ambil role dari query parameter (e.g. "Dosen" atau "Taruna")

	if role != "Taruna" && role != "Dosen" {
		http.Error(w, "Role tidak valid", http.StatusBadRequest)
		return
	}

	db, err := config.GetDB()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var notif models.Notification
	row := db.QueryRow(`
		SELECT id, judul, deskripsi, target, file_urls, created_at 
		FROM notifications 
		WHERE id = ?`, id)

	err = row.Scan(&notif.ID, &notif.Judul, &notif.Deskripsi, &notif.Target, &notif.FileURLs, &notif.CreatedAt)
	if err != nil {
		http.Error(w, "Notifikasi tidak ditemukan", http.StatusNotFound)
		return
	}

	// Filter berdasarkan target
	if !strings.Contains(notif.Target, role) {
		http.Error(w, "Notifikasi tidak ditujukan untuk pengguna ini", http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(notif)
}

func DownloadFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	fileName := vars["filename"]

	// Lokasi file
	filePath := filepath.Join("uploads", fileName)

	// Cek apakah file ada
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File tidak ditemukan", http.StatusNotFound)
		return
	}

	// Set header untuk download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/octet-stream")

	// Kirim file
	http.ServeFile(w, r, filePath)
}
