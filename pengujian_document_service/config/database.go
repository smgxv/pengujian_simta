package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func GetDB() (*sql.DB, error) {
	// Mengambil konfigurasi dari environment variables
	username := getEnv("DB_USER", "root")
	password := getEnv("DB_PASSWORD", "password")
	host := getEnv("DB_HOST", "mysql")
	port := getEnv("DB_PORT", "3306")
	dbname := getEnv("DB_NAME", "go_tugasakhir2")

	// Membuat string koneksi DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		username,
		password,
		host,
		port,
		dbname,
	)

	// Membuka koneksi database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("Error opening database: %v", err)
		return nil, err
	}

	// Mengatur konfigurasi koneksi database
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Minute * 5)

	// Mengecek koneksi database
	err = db.Ping()
	if err != nil {
		log.Printf("Error connecting to the database: %v", err)
		return nil, err
	}

	log.Printf("Successfully connected to database %s on %s:%s", dbname, host, port)
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
