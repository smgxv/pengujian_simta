package produkmanager

import (
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
)

const (
	MaxProdukSize = 5 << 30 // 5 GB
	MinProdukSize = 1 << 10 // 1 KB
)

// AllowedExtensions defines allowed file extensions for produk TA
var AllowedExtensions = []string{
	".zip", ".rar", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ova",
}

// IsAllowedExtension checks whether the file has an allowed extension
func IsAllowedExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, allowed := range AllowedExtensions {
		if ext == allowed {
			return true
		}
	}
	return false
}

// ValidateProdukFileType checks file extension and avoids dangerous file types
func ValidateProdukFileType(filename string) error {
	if !IsAllowedExtension(filename) {
		return fmt.Errorf("ekstensi file tidak diizinkan untuk produk TA")
	}

	ext := strings.ToLower(filepath.Ext(filename))
	// Optional: reject potentially dangerous executables
	blocked := []string{".exe", ".bat", ".sh", ".msi", ".js", ".php", ".py"}
	for _, b := range blocked {
		if ext == b {
			return fmt.Errorf("file executable tidak diizinkan")
		}
	}

	return nil
}

// ValidateProdukFileName sanitizes nama file produk TA
func ValidateProdukFileName(filename string) string {
	filename = filepath.Base(filename)
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return '_'
		}
	}, filename)
}

// SanitizeProdukPath memastikan path valid (no traversal)
func SanitizeProdukPath(baseDir, filename string) (string, error) {
	fullPath := filepath.Join(baseDir, filename)
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("gagal membaca path file: %v", err)
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("gagal membaca path base: %v", err)
	}

	if !strings.HasPrefix(absPath, absBase) {
		return "", fmt.Errorf("path tidak valid: traversal terdeteksi")
	}
	return fullPath, nil
}

// SaveProdukFile safely saves the uploaded file
func SaveProdukFile(file multipart.File, handler *multipart.FileHeader, uploadDir, newFilename string) (string, error) {
	// Size validation
	if handler.Size > MaxProdukSize {
		return "", fmt.Errorf("ukuran file melebihi 5GB")
	}
	if handler.Size < MinProdukSize {
		return "", fmt.Errorf("ukuran file terlalu kecil (<1KB)")
	}

	if err := ValidateProdukFileType(handler.Filename); err != nil {
		return "", err
	}

	if err := os.MkdirAll(uploadDir, 0750); err != nil {
		return "", fmt.Errorf("gagal membuat direktori upload: %v", err)
	}

	finalPath, err := SanitizeProdukPath(uploadDir, newFilename)
	if err != nil {
		return "", err
	}

	dst, err := os.OpenFile(finalPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0640)
	if err != nil {
		return "", fmt.Errorf("gagal membuat file: %v", err)
	}
	defer dst.Close()

	written, err := io.Copy(dst, io.LimitReader(file, MaxProdukSize+1))
	if err != nil {
		os.Remove(finalPath)
		return "", fmt.Errorf("gagal menyimpan file: %v", err)
	}
	if written > MaxProdukSize {
		os.Remove(finalPath)
		return "", fmt.Errorf("file terlalu besar (limit 5GB)")
	}

	return finalPath, nil
}
