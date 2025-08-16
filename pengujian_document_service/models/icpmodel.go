package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type ICPModel struct {
	db *sql.DB
}

func NewICPModel(db *sql.DB) *ICPModel {
	return &ICPModel{db: db}
}

func (m *ICPModel) Create(icp *entities.ICP) error {
	query := `
		INSERT INTO icp (
			user_id, dosen_id, topik_penelitian, keterangan, 
			file_path, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now().Format("2006-01-02 15:04:05")

	_, err := m.db.Exec(
		query,
		icp.UserID,
		icp.DosenID,
		icp.TopikPenelitian,
		icp.Keterangan,
		icp.FilePath,
		"pending", // status awal
		now,       // created_at
		now,       // updated_at
	)

	return err
}

func (m *ICPModel) GetByUserID(userID string) ([]entities.ICP, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, d.nama_lengkap as dosen_nama
        FROM icp i
        LEFT JOIN dosen d ON i.dosen_id = d.id
        WHERE i.user_id = ?
    `

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var icps []entities.ICP
	for rows.Next() {
		var icp entities.ICP
		err := rows.Scan(
			&icp.ID,
			&icp.UserID,
			&icp.DosenID,
			&icp.TopikPenelitian,
			&icp.Keterangan,
			&icp.FilePath,
			&icp.Status,
			&icp.CreatedAt,
			&icp.UpdatedAt,
			&icp.DosenNama, // Tambahkan field ini di struct ICP
		)
		if err != nil {
			return nil, err
		}
		icps = append(icps, icp)
	}
	return icps, nil
}

func (m *ICPModel) GetByID(id string) (*entities.ICP, error) {
	query := `
        SELECT i.*, d.nama_lengkap as dosen_nama 
        FROM icp i 
        LEFT JOIN dosen d ON i.dosen_id = d.id 
        WHERE i.id = ?
    `

	var icp entities.ICP
	err := m.db.QueryRow(query, id).Scan(
		&icp.ID, &icp.UserID, &icp.DosenID, &icp.TopikPenelitian,
		&icp.Keterangan, &icp.FilePath, &icp.Status, &icp.CreatedAt,
		&icp.UpdatedAt, &icp.DosenNama,
	)
	if err != nil {
		return nil, err
	}
	return &icp, nil
}

func (m *ICPModel) Update(icp *entities.ICP) error {
	query := `
        UPDATE icp 
        SET dosen_id = ?, topik_penelitian = ?, keterangan = ?, 
            file_path = ?, updated_at = NOW()
        WHERE id = ?
    `

	_, err := m.db.Exec(query,
		icp.DosenID,
		icp.TopikPenelitian,
		icp.Keterangan,
		icp.FilePath,
		icp.ID,
	)
	return err
}

func (m *ICPModel) GetByDosenID(dosenID string) ([]entities.ICP, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, t.nama_lengkap as nama_taruna, t.kelas
        FROM icp i
        LEFT JOIN taruna t ON i.user_id = t.user_id
        WHERE i.dosen_id = ?
    `

	rows, err := m.db.Query(query, dosenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var icps []entities.ICP
	for rows.Next() {
		var icp entities.ICP
		var namaTaruna sql.NullString
		var kelas sql.NullString
		err := rows.Scan(
			&icp.ID,
			&icp.UserID,
			&icp.DosenID,
			&icp.TopikPenelitian,
			&icp.Keterangan,
			&icp.FilePath,
			&icp.Status,
			&icp.CreatedAt,
			&icp.UpdatedAt,
			&namaTaruna,
			&kelas,
		)
		if err != nil {
			return nil, err
		}
		if namaTaruna.Valid {
			icp.NamaTaruna = namaTaruna.String
		} else {
			icp.NamaTaruna = ""
		}
		if kelas.Valid {
			icp.Kelas = kelas.String
		} else {
			icp.Kelas = ""
		}
		icps = append(icps, icp)
	}
	return icps, nil
}
