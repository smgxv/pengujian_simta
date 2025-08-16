package models

import (
	"database/sql"
	"document_service/entities"
)

type RevisiLaporan70Model struct {
	db *sql.DB
}

func NewRevisiLaporan70Model(db *sql.DB) *RevisiLaporan70Model {
	return &RevisiLaporan70Model{
		db: db,
	}
}

func (m *RevisiLaporan70Model) Create(revisiLaporan70 *entities.RevisiLaporan70) error {
	query := `
		INSERT INTO revisi_laporan70 (
			user_id, nama_lengkap, jurusan, 
			kelas, topik_penelitian, file_path, keterangan, 
			status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		revisiLaporan70.UserID,
		revisiLaporan70.NamaLengkap,
		revisiLaporan70.Jurusan,
		revisiLaporan70.Kelas,
		revisiLaporan70.TopikPenelitian,
		revisiLaporan70.FilePath,
		revisiLaporan70.Keterangan,
		"pending", // default status
	)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	revisiLaporan70.ID = int(id)
	return nil
}

func (m *RevisiLaporan70Model) GetByUserID(userID string) ([]entities.RevisiLaporan70, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, 
			jurusan, kelas, topik_penelitian, file_path, 
			keterangan, status, created_at, updated_at
		FROM revisi_laporan70 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var revisiLaporan70s []entities.RevisiLaporan70
	for rows.Next() {
		var revisiLaporan70 entities.RevisiLaporan70
		err := rows.Scan(
			&revisiLaporan70.ID,
			&revisiLaporan70.UserID,
			&revisiLaporan70.NamaLengkap,
			&revisiLaporan70.Jurusan,
			&revisiLaporan70.Kelas,
			&revisiLaporan70.TopikPenelitian,
			&revisiLaporan70.FilePath,
			&revisiLaporan70.Keterangan,
			&revisiLaporan70.Status,
			&revisiLaporan70.CreatedAt,
			&revisiLaporan70.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		revisiLaporan70s = append(revisiLaporan70s, revisiLaporan70)
	}

	return revisiLaporan70s, nil
}
