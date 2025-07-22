package filemanager

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Constants for file validation
const (
	MaxFileSize = 15 << 20 // 15 MB
	MinFileSize = 1 << 10  // 1 KB
)

// Allowed MIME types and their corresponding file extensions
var (
	AllowedMimeTypes = map[string][]string{
		"application/pdf": {".pdf"},
	}
)

// ValidateFileType checks if the file type is allowed
func ValidateFileType(file io.Reader, filename string) error {
	// Read first 512 bytes to determine file type
	buffer := make([]byte, 512)
	_, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("error reading file header: %v", err)
	}

	// Detect content type
	contentType := http.DetectContentType(buffer)
	ext := strings.ToLower(filepath.Ext(filename))

	// Check if content type is allowed
	if contentType != "application/pdf" {
		return fmt.Errorf("hanya file PDF yang diizinkan, mohon upload file dengan tipe PDF")
	}

	// Verify file extension
	if ext != ".pdf" {
		return fmt.Errorf("ekstensi file harus .pdf")
	}

	return nil
}

// ValidateFileName checks if the filename is safe
func ValidateFileName(filename string) string {
	// Remove any path components
	filename = filepath.Base(filename)

	// Remove any potentially dangerous characters
	filename = strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return '_'
		}
	}, filename)

	return filename
}

// SanitizeFilePath ensures the file path is within the allowed directory
func SanitizeFilePath(baseDir, filename string) (string, error) {
	fullPath := filepath.Join(baseDir, filename)

	// Convert to absolute path
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("error getting absolute path: %v", err)
	}

	// Ensure the path is within the base directory
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("error getting base directory path: %v", err)
	}

	if !strings.HasPrefix(absPath, absBaseDir) {
		return "", fmt.Errorf("invalid file path: path traversal detected")
	}

	return fullPath, nil
}

// EnsureUploadDir creates required upload directories if they don't exist
func EnsureUploadDir() error {
	dirs := []string{
		"uploads/icp",
		"uploads/proposal",
		"uploads/laporan70",
		"uploads/laporan100",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("error creating directory %s: %v", dir, err)
		}
	}
	return nil
}

// SaveUploadedFile handles the complete process of saving an uploaded file securely
func SaveUploadedFile(file io.Reader, handler *multipart.FileHeader, uploadDir, filename string) (string, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(uploadDir, 0750); err != nil {
		return "", fmt.Errorf("error creating upload directory: %v", err)
	}

	// Validate and sanitize file path
	filePath, err := SanitizeFilePath(uploadDir, filename)
	if err != nil {
		return "", fmt.Errorf("invalid file path: %v", err)
	}

	// Create the file with restricted permissions
	dst, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return "", fmt.Errorf("error creating file: %v", err)
	}
	defer dst.Close()

	// Copy the uploaded file with additional validation
	written, err := io.Copy(dst, io.LimitReader(file, MaxFileSize))
	if err != nil {
		os.Remove(filePath) // Clean up on error
		return "", fmt.Errorf("error saving file: %v", err)
	}
	if written > MaxFileSize {
		os.Remove(filePath) // Clean up on error
		return "", fmt.Errorf("file too large")
	}

	return filePath, nil
}

// LargeFileUploadMiddleware handles large file uploads
func LargeFileUploadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply to upload endpoints
		if strings.Contains(r.URL.Path, "/upload/") {
			// Set response headers
			w.Header().Set("Content-Type", "application/json")

			// Set max body size to 15MB
			r.Body = http.MaxBytesReader(w, r.Body, MaxFileSize)

			// Check content length if provided
			if r.ContentLength > MaxFileSize {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "error",
					"message": "File terlalu besar. Maksimal ukuran file adalah 15MB",
				})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
