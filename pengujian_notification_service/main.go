package main

import (
	"log"
	"net/http"
	"os"

	"notification_service/handlers"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	r := mux.NewRouter()

	// Buat folder uploads kalau belum ada
	if err := os.MkdirAll("uploads", os.ModePerm); err != nil {
		log.Fatal("Gagal membuat folder uploads:", err)
	}

	// Register endpoint
	r.HandleFunc("/broadcast", handlers.BroadcastNotification).Methods("POST", "OPTIONS")
	r.HandleFunc("/notifications", handlers.GetNotifications).Methods("GET", "OPTIONS")
	r.HandleFunc("/notification/{id}", handlers.GetNotificationByID).Methods("GET", "OPTIONS")
	r.HandleFunc("/download/{filename}", handlers.DownloadFile).Methods("GET", "OPTIONS")

	// Setup CORS agar frontend (port 8080) bisa akses
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://104.43.89.154:8085"}, // sesuaikan jika pakai domain lain
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// Bungkus router dengan CORS handler
	handler := c.Handler(r)

	// Jalankan server di port 8083
	log.Println("✅ Notification Service running on :8088")
	log.Fatal(http.ListenAndServe(":8088", handler))
}
