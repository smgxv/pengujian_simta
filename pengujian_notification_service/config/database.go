package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// GetDB mengembalikan koneksi database MySQL
func GetDB() (*sql.DB, error) {
	username := getEnv("DB_USER", "root")
	password := getEnv("DB_PASSWORD", "password")
	host := getEnv("DB_HOST", "mysql")
	port := getEnv("DB_PORT", "3306")
	dbname := getEnv("DB_NAME", "go_tugasakhir2")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		username,
		password,
		host,
		port,
		dbname,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("❌ Gagal membuka koneksi database: %v", err)
		return nil, err
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Minute * 5)

	err = db.Ping()
	if err != nil {
		log.Printf("❌ Gagal terhubung ke database: %v", err)
		return nil, err
	}

	log.Printf("✅ Terhubung ke database %s di %s:%s", dbname, host, port)
	return db, nil
}

// getEnv mengambil nilai environment variable atau nilai default
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
