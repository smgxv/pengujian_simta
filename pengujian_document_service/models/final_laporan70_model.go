package models

import (
	"database/sql"
	"document_service/entities"
)

type FinalLaporan70Model struct {
	db *sql.DB
}

func NewFinalLaporan70Model(db *sql.DB) *FinalLaporan70Model {
	return &FinalLaporan70Model{
		db: db,
	}
}

// Create menyimpan final laporan70 + form bimbingan + file pendukung (JSON string)
func (m *FinalLaporan70Model) Create(finalLaporan70 *entities.FinalLaporan70) error {
	query := `
		INSERT INTO final_laporan70 (
			user_id, nama_lengkap, jurusan,
			kelas, topik_penelitian, file_path,
			form_bimbingan_path, file_pendukung_path, keterangan, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		finalLaporan70.UserID,
		finalLaporan70.NamaLengkap,
		finalLaporan70.Jurusan,
		finalLaporan70.Kelas,
		finalLaporan70.TopikPenelitian,
		finalLaporan70.FilePath,
		finalLaporan70.FormBimbinganPath,
		finalLaporan70.FilePendukungPath, // <- JSON array string
		finalLaporan70.Keterangan,
		"pending", // default status
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	finalLaporan70.ID = int(id)
	return nil
}

// GetByUserID mengembalikan data termasuk file_pendukung_path
func (m *FinalLaporan70Model) GetByUserID(userID string) ([]entities.FinalLaporan70, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, 
			jurusan, kelas, topik_penelitian, file_path, 
			form_bimbingan_path, file_pendukung_path, keterangan, status, 
			created_at, updated_at
		FROM final_laporan70 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var finalLaporan70s []entities.FinalLaporan70
	for rows.Next() {
		var finalLaporan70 entities.FinalLaporan70
		err := rows.Scan(
			&finalLaporan70.ID,
			&finalLaporan70.UserID,
			&finalLaporan70.NamaLengkap,
			&finalLaporan70.Jurusan,
			&finalLaporan70.Kelas,
			&finalLaporan70.TopikPenelitian,
			&finalLaporan70.FilePath,
			&finalLaporan70.FormBimbinganPath,
			&finalLaporan70.FilePendukungPath,
			&finalLaporan70.Keterangan,
			&finalLaporan70.Status,
			&finalLaporan70.CreatedAt,
			&finalLaporan70.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		finalLaporan70s = append(finalLaporan70s, finalLaporan70)
	}

	return finalLaporan70s, nil
}
