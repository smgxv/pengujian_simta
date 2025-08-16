package models

import (
	"database/sql"
	"document_service/entities"
)

type FinalICPModel struct {
	db *sql.DB
}

func NewFinalICPModel(db *sql.DB) *FinalICPModel {
	return &FinalICPModel{
		db: db,
	}
}

func (m *FinalICPModel) Create(finalICP *entities.FinalICP) error {
	query := `
		INSERT INTO final_icp (
			user_id, nama_lengkap, jurusan, 
			kelas, topik_penelitian, file_path, file_pendukung_path, keterangan, 
			status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		finalICP.UserID,
		finalICP.NamaLengkap,
		finalICP.Jurusan,
		finalICP.Kelas,
		finalICP.TopikPenelitian,
		finalICP.FilePath,
		finalICP.FilePendukungPath, // << kolom baru
		finalICP.Keterangan,
		"pending", // default status
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	finalICP.ID = int(id)
	return nil
}

func (m *FinalICPModel) GetByUserID(userID string) ([]entities.FinalICP, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, 
			jurusan, kelas, topik_penelitian, file_path, file_pendukung_path, 
			keterangan, status, created_at, updated_at
		FROM final_icp 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var finalICPs []entities.FinalICP
	for rows.Next() {
		var finalICP entities.FinalICP
		err := rows.Scan(
			&finalICP.ID,
			&finalICP.UserID,
			&finalICP.NamaLengkap,
			&finalICP.Jurusan,
			&finalICP.Kelas,
			&finalICP.TopikPenelitian,
			&finalICP.FilePath,
			&finalICP.FilePendukungPath, // << kolom baru
			&finalICP.Keterangan,
			&finalICP.Status,
			&finalICP.CreatedAt,
			&finalICP.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		finalICPs = append(finalICPs, finalICP)
	}

	return finalICPs, nil
}
