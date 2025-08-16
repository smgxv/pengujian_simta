package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type ReviewLaporan100DosenModel struct {
	db *sql.DB
}

func NewReviewLaporan100DosenModel(db *sql.DB) *ReviewLaporan100DosenModel {
	return &ReviewLaporan100DosenModel{db: db}
}

func (m *ReviewLaporan100DosenModel) Create(review *entities.ReviewLaporan100) error {
	query := `
		INSERT INTO review_laporan100_dosen (
			laporan100_id, dosen_id, taruna_id, topik_penelitian, 
			keterangan, file_path, cycle_number,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := m.db.Exec(
		query,
		review.Laporan100ID,
		review.DosenID,
		review.TarunaID,
		review.TopikPenelitian,
		review.Keterangan,
		review.FilePath,
		1, // cycle_number awal
		now,
		now,
	)
	return err
}

func (m *ReviewLaporan100DosenModel) GetByDosenID(dosenID string) ([]entities.ReviewLaporan100, error) {
	query := `
		SELECT 
			r.id, r.laporan100_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna
		FROM review_laporan100_dosen r
		LEFT JOIN taruna t ON r.taruna_id = t.id
		WHERE r.dosen_id = ?
		ORDER BY r.created_at DESC
	`

	rows, err := m.db.Query(query, dosenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []entities.ReviewLaporan100
	for rows.Next() {
		var review entities.ReviewLaporan100
		var namaTaruna sql.NullString
		err := rows.Scan(
			&review.ID,
			&review.Laporan100ID,
			&review.TarunaID,
			&review.DosenID,
			&review.CycleNumber,
			&review.TopikPenelitian,
			&review.FilePath,
			&review.Keterangan,
			&review.CreatedAt,
			&review.UpdatedAt,
			&namaTaruna,
		)
		if err != nil {
			return nil, err
		}
		if namaTaruna.Valid {
			review.NamaTaruna = namaTaruna.String
		}
		reviews = append(reviews, review)
	}
	return reviews, nil
}

func (m *ReviewLaporan100DosenModel) GetByTarunaID(userID string) ([]entities.ReviewLaporan100, error) {
	query := `
		SELECT 
			r.id, r.laporan100_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, d.nama_lengkap as dosen_nama
		FROM review_laporan100_dosen r
		LEFT JOIN dosen d ON r.dosen_id = d.id
		LEFT JOIN taruna t ON r.taruna_id = t.id
		WHERE t.user_id = ?
		ORDER BY r.created_at DESC
	`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []entities.ReviewLaporan100
	for rows.Next() {
		var review entities.ReviewLaporan100
		var dosenNama sql.NullString
		err := rows.Scan(
			&review.ID,
			&review.Laporan100ID,
			&review.TarunaID,
			&review.DosenID,
			&review.CycleNumber,
			&review.TopikPenelitian,
			&review.FilePath,
			&review.Keterangan,
			&review.CreatedAt,
			&review.UpdatedAt,
			&dosenNama,
		)
		if err != nil {
			return nil, err
		}
		if dosenNama.Valid {
			review.DosenNama = dosenNama.String
		}
		reviews = append(reviews, review)
	}
	return reviews, nil
}
