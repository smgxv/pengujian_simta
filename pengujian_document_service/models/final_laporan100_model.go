package models

import (
	"database/sql"
	"document_service/entities"
)

type FinalLaporan100Model struct {
	db *sql.DB
}

func NewFinalLaporan100Model(db *sql.DB) *FinalLaporan100Model {
	return &FinalLaporan100Model{
		db: db,
	}
}

// Create menyimpan final laporan100 + form bimbingan + file pendukung (JSON string)
func (m *FinalLaporan100Model) Create(finalLaporan100 *entities.FinalLaporan100) error {
	query := `
		INSERT INTO final_laporan100 (
			user_id, nama_lengkap, jurusan,
			kelas, topik_penelitian, file_path,
			form_bimbingan_path, file_pendukung_path, keterangan, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		finalLaporan100.UserID,
		finalLaporan100.NamaLengkap,
		finalLaporan100.Jurusan,
		finalLaporan100.Kelas,
		finalLaporan100.TopikPenelitian,
		finalLaporan100.FilePath,
		finalLaporan100.FormBimbinganPath,
		finalLaporan100.FilePendukungPath, // <- JSON array string
		finalLaporan100.Keterangan,
		"pending", // default status
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	finalLaporan100.ID = int(id)
	return nil
}

// GetByUserID mengembalikan data termasuk file_pendukung_path
func (m *FinalLaporan100Model) GetByUserID(userID string) ([]entities.FinalLaporan100, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, 
			jurusan, kelas, topik_penelitian, file_path, 
			form_bimbingan_path, file_pendukung_path, keterangan, status, 
			created_at, updated_at
		FROM final_laporan100 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var finalLaporan100s []entities.FinalLaporan100
	for rows.Next() {
		var finalLaporan100 entities.FinalLaporan100
		err := rows.Scan(
			&finalLaporan100.ID,
			&finalLaporan100.UserID,
			&finalLaporan100.NamaLengkap,
			&finalLaporan100.Jurusan,
			&finalLaporan100.Kelas,
			&finalLaporan100.TopikPenelitian,
			&finalLaporan100.FilePath,
			&finalLaporan100.FormBimbinganPath,
			&finalLaporan100.FilePendukungPath,
			&finalLaporan100.Keterangan,
			&finalLaporan100.Status,
			&finalLaporan100.CreatedAt,
			&finalLaporan100.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		finalLaporan100s = append(finalLaporan100s, finalLaporan100)
	}

	return finalLaporan100s, nil
}
