package config

import (
	"database/sql" // Paket untuk berinteraksi dengan database menggunakan SQL
	"fmt"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql" // Import driver MySQL untuk Go (digunakan untuk koneksi ke database MySQL)
)

// Fungsi DBConn digunakan untuk menginisialisasi koneksi ke database
func DBConn() (db *sql.DB, err error) {
	// Mengambil konfigurasi dari environment variables
	dbHost := getEnv("DB_HOST", "mysql")
	dbUser := getEnv("DB_USER", "root")
	dbPass := getEnv("DB_PASSWORD", "password")
	dbName := getEnv("DB_NAME", "go_tugasakhir2")

	// Format DSN untuk MySQL
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", dbUser, dbPass, dbHost, dbName)

	// Membuka koneksi ke database
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	// Konfigurasi connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Minute * 5)

	// Cek koneksi database
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Helper function untuk mengambil environment variable dengan nilai default
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
