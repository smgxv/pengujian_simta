package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

func InsertSeminarProposal(db *sql.DB, proposal *entities.SeminarProposal) error {
	query := `
		INSERT INTO seminar_proposal (
			user_id, topik_penelitian, file_proposal_path,
			ketua_penguji_id, penguji1_id, penguji2_id,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	_, err := db.Exec(query,
		proposal.UserID,
		proposal.TopikPenelitian,
		proposal.FileProposalPath,
		proposal.KetuaPengujiID,
		proposal.Penguji1ID,
		proposal.Penguji2ID,
		now,
		now,
	)

	return err
}

func GetSeminarProposalByUserID(db *sql.DB, userID int) ([]entities.SeminarProposal, error) {
	query := `
		SELECT id, user_id, topik_penelitian, file_proposal_path,
		       ketua_penguji_id, penguji1_id, penguji2_id,
		       created_at, updated_at
		FROM seminar_proposal
		WHERE user_id = ?
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proposals []entities.SeminarProposal
	for rows.Next() {
		var proposal entities.SeminarProposal
		err := rows.Scan(
			&proposal.ID,
			&proposal.UserID,
			&proposal.TopikPenelitian,
			&proposal.FileProposalPath,
			&proposal.KetuaPengujiID,
			&proposal.Penguji1ID,
			&proposal.Penguji2ID,
			&proposal.CreatedAt,
			&proposal.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, proposal)
	}

	return proposals, nil
}
