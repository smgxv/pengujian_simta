package models

import (
	"database/sql"
	"document_service/entities"
)

type FinalProposalModel struct {
	db *sql.DB
}

func NewFinalProposalModel(db *sql.DB) *FinalProposalModel {
	return &FinalProposalModel{
		db: db,
	}
}

// Create menyimpan final proposal + form bimbingan + file pendukung (JSON string)
func (m *FinalProposalModel) Create(finalProposal *entities.FinalProposal) error {
	query := `
		INSERT INTO final_proposal (
			user_id, nama_lengkap, jurusan,
			kelas, topik_penelitian, file_path,
			form_bimbingan_path, file_pendukung_path, keterangan, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		finalProposal.UserID,
		finalProposal.NamaLengkap,
		finalProposal.Jurusan,
		finalProposal.Kelas,
		finalProposal.TopikPenelitian,
		finalProposal.FilePath,
		finalProposal.FormBimbinganPath,
		finalProposal.FilePendukungPath, // <- JSON array string
		finalProposal.Keterangan,
		"pending", // default status
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	finalProposal.ID = int(id)
	return nil
}

// GetByUserID mengembalikan data termasuk file_pendukung_path
func (m *FinalProposalModel) GetByUserID(userID string) ([]entities.FinalProposal, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, 
			jurusan, kelas, topik_penelitian, file_path, 
			form_bimbingan_path, file_pendukung_path, keterangan, status, 
			created_at, updated_at
		FROM final_proposal 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var finalProposals []entities.FinalProposal
	for rows.Next() {
		var finalProposal entities.FinalProposal
		err := rows.Scan(
			&finalProposal.ID,
			&finalProposal.UserID,
			&finalProposal.NamaLengkap,
			&finalProposal.Jurusan,
			&finalProposal.Kelas,
			&finalProposal.TopikPenelitian,
			&finalProposal.FilePath,
			&finalProposal.FormBimbinganPath,
			&finalProposal.FilePendukungPath,
			&finalProposal.Keterangan,
			&finalProposal.Status,
			&finalProposal.CreatedAt,
			&finalProposal.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		finalProposals = append(finalProposals, finalProposal)
	}

	return finalProposals, nil
}
