package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type Laporan100Model struct {
	db *sql.DB
}

func NewLaporan100Model(db *sql.DB) *Laporan100Model {
	return &Laporan100Model{db: db}
}

func (m *Laporan100Model) Create(laporan100 *entities.Laporan100) error {
	query := `
		INSERT INTO laporan_100 (
			user_id, dosen_id, topik_penelitian, keterangan, 
			file_path, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now().Format("2006-01-02 15:04:05")

	_, err := m.db.Exec(
		query,
		laporan100.UserID,
		laporan100.DosenID,
		laporan100.TopikPenelitian,
		laporan100.Keterangan,
		laporan100.FilePath,
		"pending", // status awal
		now,       // created_at
		now,       // updated_at
	)

	return err
}

func (m *Laporan100Model) GetByUserID(userID string) ([]entities.Laporan100, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, d.nama_lengkap as dosen_nama
        FROM laporan_100 i
        LEFT JOIN dosen d ON i.dosen_id = d.id
        WHERE i.user_id = ?
    `

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var laporan100s []entities.Laporan100
	for rows.Next() {
		var laporan100 entities.Laporan100
		err := rows.Scan(
			&laporan100.ID,
			&laporan100.UserID,
			&laporan100.DosenID,
			&laporan100.TopikPenelitian,
			&laporan100.Keterangan,
			&laporan100.FilePath,
			&laporan100.Status,
			&laporan100.CreatedAt,
			&laporan100.UpdatedAt,
			&laporan100.DosenNama, // Tambahkan field ini di struct ICP
		)
		if err != nil {
			return nil, err
		}
		laporan100s = append(laporan100s, laporan100)
	}
	return laporan100s, nil
}

func (m *Laporan100Model) GetByID(id string) (*entities.Laporan100, error) {
	query := `
        SELECT i.*, d.nama_lengkap as dosen_nama 
        FROM laporan_100 i 
        LEFT JOIN dosen d ON i.dosen_id = d.id 
        WHERE i.id = ?
    `

	var laporan100 entities.Laporan100
	err := m.db.QueryRow(query, id).Scan(
		&laporan100.ID, &laporan100.UserID, &laporan100.DosenID, &laporan100.TopikPenelitian,
		&laporan100.Keterangan, &laporan100.FilePath, &laporan100.Status, &laporan100.CreatedAt,
		&laporan100.UpdatedAt, &laporan100.DosenNama,
	)
	if err != nil {
		return nil, err
	}
	return &laporan100, nil
}

func (m *Laporan100Model) Update(laporan100 *entities.Laporan100) error {
	query := `
        UPDATE laporan_100 
        SET dosen_id = ?, topik_penelitian = ?, keterangan = ?, 
            file_path = ?, updated_at = NOW()
        WHERE id = ?
    `

	_, err := m.db.Exec(query,
		laporan100.DosenID,
		laporan100.TopikPenelitian,
		laporan100.Keterangan,
		laporan100.FilePath,
		laporan100.ID,
	)
	return err
}

func (m *Laporan100Model) GetByDosenID(dosenID string) ([]entities.Laporan100, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, t.nama_lengkap as nama_taruna, t.kelas
        FROM laporan_100 i
        LEFT JOIN taruna t ON i.user_id = t.user_id
        WHERE i.dosen_id = ?
    `

	rows, err := m.db.Query(query, dosenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var laporan100s []entities.Laporan100
	for rows.Next() {
		var laporan100 entities.Laporan100
		var namaTaruna sql.NullString
		var kelas sql.NullString
		err := rows.Scan(
			&laporan100.ID,
			&laporan100.UserID,
			&laporan100.DosenID,
			&laporan100.TopikPenelitian,
			&laporan100.Keterangan,
			&laporan100.FilePath,
			&laporan100.Status,
			&laporan100.CreatedAt,
			&laporan100.UpdatedAt,
			&namaTaruna,
			&kelas,
		)
		if err != nil {
			return nil, err
		}
		if namaTaruna.Valid {
			laporan100.NamaTaruna = namaTaruna.String
		} else {
			laporan100.NamaTaruna = ""
		}
		if kelas.Valid {
			laporan100.Kelas = kelas.String
		} else {
			laporan100.Kelas = ""
		}
		laporan100s = append(laporan100s, laporan100)
	}
	return laporan100s, nil
}
