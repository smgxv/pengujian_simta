package models

import (
	"database/sql"
	"document_service/entities"
)

type RevisiICPModel struct {
	db *sql.DB
}

func NewRevisiICPModel(db *sql.DB) *RevisiICPModel {
	return &RevisiICPModel{
		db: db,
	}
}

func (m *RevisiICPModel) Create(revisiICP *entities.RevisiICP) error {
	query := `
		INSERT INTO revisi_icp (
			user_id, nama_lengkap, jurusan, 
			kelas, topik_penelitian, file_path, keterangan, 
			status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		revisiICP.UserID,
		revisiICP.NamaLengkap,
		revisiICP.Jurusan,
		revisiICP.Kelas,
		revisiICP.TopikPenelitian,
		revisiICP.FilePath,
		revisiICP.Keterangan,
		"pending", // default status
	)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	revisiICP.ID = int(id)
	return nil
}

func (m *RevisiICPModel) GetByUserID(userID string) ([]entities.RevisiICP, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, 
			jurusan, kelas, topik_penelitian, file_path, 
			keterangan, status, created_at, updated_at
		FROM revisi_icp 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var revisiICPs []entities.RevisiICP
	for rows.Next() {
		var revisiICP entities.RevisiICP
		err := rows.Scan(
			&revisiICP.ID,
			&revisiICP.UserID,
			&revisiICP.NamaLengkap,
			&revisiICP.Jurusan,
			&revisiICP.Kelas,
			&revisiICP.TopikPenelitian,
			&revisiICP.FilePath,
			&revisiICP.Keterangan,
			&revisiICP.Status,
			&revisiICP.CreatedAt,
			&revisiICP.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		revisiICPs = append(revisiICPs, revisiICP)
	}

	return revisiICPs, nil
}
