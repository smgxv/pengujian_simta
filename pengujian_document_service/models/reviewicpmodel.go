package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type ReviewICPModel struct {
	db *sql.DB
}

func NewReviewICPModel(db *sql.DB) *ReviewICPModel {
	return &ReviewICPModel{db: db}
}

func (m *ReviewICPModel) Create(review *entities.ReviewICP) error {
	query := `
		INSERT INTO review_icp (
			dosen_id, taruna_id, topik_penelitian, keterangan, 
			file_path, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := m.db.Exec(
		query,
		review.DosenID,
		review.TarunaID,
		review.TopikPenelitian,
		review.Keterangan,
		review.FilePath,
		"pending",
		now,
		now,
	)
	return err
}

func (m *ReviewICPModel) GetByDosenID(dosenID string) ([]entities.ReviewICP, error) {
	query := `
		SELECT 
			r.id, r.dosen_id, r.taruna_id, r.topik_penelitian,
			r.keterangan, r.file_path, r.status, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna
		FROM review_icp r
		LEFT JOIN taruna t ON r.taruna_id = t.user_id
		WHERE r.dosen_id = ?
	`

	rows, err := m.db.Query(query, dosenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []entities.ReviewICP
	for rows.Next() {
		var review entities.ReviewICP
		var namaTaruna sql.NullString
		err := rows.Scan(
			&review.ID,
			&review.DosenID,
			&review.TarunaID,
			&review.TopikPenelitian,
			&review.Keterangan,
			&review.FilePath,
			&review.Status,
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

func (m *ReviewICPModel) GetByTarunaID(tarunaID string) ([]entities.ReviewICP, error) {
	query := `
		SELECT 
			r.id, r.dosen_id, r.taruna_id, r.topik_penelitian,
			r.keterangan, r.file_path, r.status, r.created_at,
			r.updated_at, d.nama_lengkap as dosen_nama
		FROM review_icp r
		LEFT JOIN dosen d ON r.dosen_id = d.id
		WHERE r.taruna_id = ?
	`

	rows, err := m.db.Query(query, tarunaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []entities.ReviewICP
	for rows.Next() {
		var review entities.ReviewICP
		var dosenNama sql.NullString
		err := rows.Scan(
			&review.ID,
			&review.DosenID,
			&review.TarunaID,
			&review.TopikPenelitian,
			&review.Keterangan,
			&review.FilePath,
			&review.Status,
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
