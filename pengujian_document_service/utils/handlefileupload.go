package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func HandleFileUpload(r *http.Request, formField, userID, prefix string) (string, error) {
	file, handler, err := r.FormFile(formField)
	if err != nil {
		return "", fmt.Errorf("Gagal mengambil file '%s': %v", formField, err)
	}
	defer file.Close()

	uploadDir := "uploads/finalproposal"
	if err := os.MkdirAll(uploadDir, 0777); err != nil {
		return "", fmt.Errorf("Gagal membuat folder upload: %v", err)
	}

	filename := fmt.Sprintf("%s_%s_%s_%s", prefix, userID, time.Now().Format("20060102150405"), handler.Filename)
	filePath := filepath.Join(uploadDir, filename)

	dst, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("Gagal membuat file: %v", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		os.Remove(filePath)
		return "", fmt.Errorf("Gagal menyimpan file: %v", err)
	}

	return filePath, nil
}
