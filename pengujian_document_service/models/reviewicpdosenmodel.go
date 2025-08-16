package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type ReviewICPDosenModel struct {
	db *sql.DB
}

func NewReviewICPDosenModel(db *sql.DB) *ReviewICPDosenModel {
	return &ReviewICPDosenModel{db: db}
}

func (m *ReviewICPDosenModel) Create(review *entities.ReviewICP) error {
	query := `
		INSERT INTO review_icp_dosen (
			icp_id, dosen_id, taruna_id, topik_penelitian, 
			keterangan, file_path, cycle_number,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := m.db.Exec(
		query,
		review.ICPID,
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

func (m *ReviewICPDosenModel) GetByDosenID(dosenID string) ([]entities.ReviewICP, error) {
	query := `
		SELECT 
			r.id, r.icp_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna
		FROM review_icp_dosen r
		LEFT JOIN taruna t ON r.taruna_id = t.id
		WHERE r.dosen_id = ?
		ORDER BY r.created_at DESC
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
			&review.ICPID,
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

func (m *ReviewICPDosenModel) GetByTarunaID(userID string) ([]entities.ReviewICP, error) {
	query := `
		SELECT 
			r.id, r.icp_id, r.taruna_id, r.dosen_id, r.cycle_number,
			r.topik_penelitian, r.file_path, r.keterangan, r.created_at,
			r.updated_at, d.nama_lengkap as dosen_nama
		FROM review_icp_dosen r
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

	var reviews []entities.ReviewICP
	for rows.Next() {
		var review entities.ReviewICP
		var dosenNama sql.NullString
		err := rows.Scan(
			&review.ID,
			&review.ICPID,
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
