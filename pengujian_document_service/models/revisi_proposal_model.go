package models

import (
	"database/sql"
	"document_service/entities"
)

type RevisiProposalModel struct {
	db *sql.DB
}

func NewRevisiProposalModel(db *sql.DB) *RevisiProposalModel {
	return &RevisiProposalModel{
		db: db,
	}
}

func (m *RevisiProposalModel) Create(revisiProposal *entities.RevisiProposal) error {
	query := `
		INSERT INTO revisi_proposal (
			user_id, nama_lengkap, jurusan, 
			kelas, topik_penelitian, file_path, keterangan, 
			status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		revisiProposal.UserID,
		revisiProposal.NamaLengkap,
		revisiProposal.Jurusan,
		revisiProposal.Kelas,
		revisiProposal.TopikPenelitian,
		revisiProposal.FilePath,
		revisiProposal.Keterangan,
		"pending", // default status
	)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	revisiProposal.ID = int(id)
	return nil
}

func (m *RevisiProposalModel) GetByUserID(userID string) ([]entities.RevisiProposal, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, 
			jurusan, kelas, topik_penelitian, file_path, 
			keterangan, status, created_at, updated_at
		FROM revisi_proposal 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var revisiProposals []entities.RevisiProposal
	for rows.Next() {
		var revisiProposal entities.RevisiProposal
		err := rows.Scan(
			&revisiProposal.ID,
			&revisiProposal.UserID,
			&revisiProposal.NamaLengkap,
			&revisiProposal.Jurusan,
			&revisiProposal.Kelas,
			&revisiProposal.TopikPenelitian,
			&revisiProposal.FilePath,
			&revisiProposal.Keterangan,
			&revisiProposal.Status,
			&revisiProposal.CreatedAt,
			&revisiProposal.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		revisiProposals = append(revisiProposals, revisiProposal)
	}

	return revisiProposals, nil
}
