package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type Laporan70Model struct {
	db *sql.DB
}

func NewLaporan70Model(db *sql.DB) *Laporan70Model {
	return &Laporan70Model{db: db}
}

func (m *Laporan70Model) Create(laporan70 *entities.Laporan70) error {
	query := `
		INSERT INTO laporan_70 (
			user_id, dosen_id, topik_penelitian, keterangan, 
			file_path, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now().Format("2006-01-02 15:04:05")

	_, err := m.db.Exec(
		query,
		laporan70.UserID,
		laporan70.DosenID,
		laporan70.TopikPenelitian,
		laporan70.Keterangan,
		laporan70.FilePath,
		"pending", // status awal
		now,       // created_at
		now,       // updated_at
	)

	return err
}

func (m *Laporan70Model) GetByUserID(userID string) ([]entities.Laporan70, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, d.nama_lengkap as dosen_nama
        FROM laporan_70 i
        LEFT JOIN dosen d ON i.dosen_id = d.id
        WHERE i.user_id = ?
    `

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var laporan70s []entities.Laporan70
	for rows.Next() {
		var laporan70 entities.Laporan70
		err := rows.Scan(
			&laporan70.ID,
			&laporan70.UserID,
			&laporan70.DosenID,
			&laporan70.TopikPenelitian,
			&laporan70.Keterangan,
			&laporan70.FilePath,
			&laporan70.Status,
			&laporan70.CreatedAt,
			&laporan70.UpdatedAt,
			&laporan70.DosenNama, // Tambahkan field ini di struct ICP
		)
		if err != nil {
			return nil, err
		}
		laporan70s = append(laporan70s, laporan70)
	}
	return laporan70s, nil
}

func (m *Laporan70Model) GetByID(id string) (*entities.Laporan70, error) {
	query := `
        SELECT i.*, d.nama_lengkap as dosen_nama 
        FROM laporan_70 i 
        LEFT JOIN dosen d ON i.dosen_id = d.id 
        WHERE i.id = ?
    `

	var laporan70 entities.Laporan70
	err := m.db.QueryRow(query, id).Scan(
		&laporan70.ID, &laporan70.UserID, &laporan70.DosenID, &laporan70.TopikPenelitian,
		&laporan70.Keterangan, &laporan70.FilePath, &laporan70.Status, &laporan70.CreatedAt,
		&laporan70.UpdatedAt, &laporan70.DosenNama,
	)
	if err != nil {
		return nil, err
	}
	return &laporan70, nil
}

func (m *Laporan70Model) Update(laporan70 *entities.Laporan70) error {
	query := `
        UPDATE laporan_70 
        SET dosen_id = ?, topik_penelitian = ?, keterangan = ?, 
            file_path = ?, updated_at = NOW()
        WHERE id = ?
    `

	_, err := m.db.Exec(query,
		laporan70.DosenID,
		laporan70.TopikPenelitian,
		laporan70.Keterangan,
		laporan70.FilePath,
		laporan70.ID,
	)
	return err
}

func (m *Laporan70Model) GetByDosenID(dosenID string) ([]entities.Laporan70, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, t.nama_lengkap as nama_taruna, t.kelas
        FROM laporan_70 i
        LEFT JOIN taruna t ON i.user_id = t.user_id
        WHERE i.dosen_id = ?
    `

	rows, err := m.db.Query(query, dosenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var laporan70s []entities.Laporan70
	for rows.Next() {
		var laporan70 entities.Laporan70
		var namaTaruna sql.NullString
		var kelas sql.NullString
		err := rows.Scan(
			&laporan70.ID,
			&laporan70.UserID,
			&laporan70.DosenID,
			&laporan70.TopikPenelitian,
			&laporan70.Keterangan,
			&laporan70.FilePath,
			&laporan70.Status,
			&laporan70.CreatedAt,
			&laporan70.UpdatedAt,
			&namaTaruna,
			&kelas,
		)
		if err != nil {
			return nil, err
		}
		if namaTaruna.Valid {
			laporan70.NamaTaruna = namaTaruna.String
		} else {
			laporan70.NamaTaruna = ""
		}
		if kelas.Valid {
			laporan70.Kelas = kelas.String
		} else {
			laporan70.Kelas = ""
		}
		laporan70s = append(laporan70s, laporan70)
	}
	return laporan70s, nil
}
