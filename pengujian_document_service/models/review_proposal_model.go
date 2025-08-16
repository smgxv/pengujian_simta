package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type ReviewProposalModel struct {
	db *sql.DB
}

func NewReviewProposalModel(db *sql.DB) *ReviewProposalModel {
	return &ReviewProposalModel{db: db}
}

func (m *ReviewProposalModel) Create(review *entities.ReviewICP) error {
	query := `
		INSERT INTO review_proposal (
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

func (m *ReviewProposalModel) GetByDosenID(dosenID string) ([]entities.ReviewProposal, error) {
	query := `
		SELECT 
			r.id, r.dosen_id, r.taruna_id, r.topik_penelitian,
			r.keterangan, r.file_path, r.status, r.created_at,
			r.updated_at, t.nama_lengkap as nama_taruna
		FROM review_proposal r
		LEFT JOIN taruna t ON r.taruna_id = t.user_id
		WHERE r.dosen_id = ?
	`

	rows, err := m.db.Query(query, dosenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []entities.ReviewProposal
	for rows.Next() {
		var review entities.ReviewProposal
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

func (m *ReviewProposalModel) GetByTarunaID(tarunaID string) ([]entities.ReviewProposal, error) {
	query := `
		SELECT 
			r.*, d.nama_lengkap as dosen_nama
		FROM review_proposal r
		LEFT JOIN dosen d ON r.dosen_id = d.id
		WHERE r.taruna_id = ?
		ORDER BY r.created_at DESC
	`

	rows, err := m.db.Query(query, tarunaID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []entities.ReviewProposal
	for rows.Next() {
		var review entities.ReviewProposal
		err := rows.Scan(
			&review.ID,
			&review.ProposalID,
			&review.TarunaID,
			&review.DosenID,
			&review.TopikPenelitian,
			&review.FilePath,
			&review.Keterangan,
			&review.CycleNumber,
			&review.CreatedAt,
			&review.UpdatedAt,
			&review.DosenNama,
		)
		if err != nil {
			return nil, err
		}
		reviews = append(reviews, review)
	}
	return reviews, nil
}
