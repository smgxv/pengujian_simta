// models/dosbing_model.go
package models

import (
	"database/sql"
	"fmt"
	"user_service/config"
	"user_service/entities"
)

type PengujiProposalModel struct {
	DB *sql.DB
}

func NewPengujiProposalModel() (*PengujiProposalModel, error) {
	db, err := config.ConnectDB()
	if err != nil {
		return nil, err
	}
	return &PengujiProposalModel{DB: db}, nil
}

func (m *PengujiProposalModel) AssignPengujiProposal(p *entities.PengujiProposal) error {
	// Ambil user_id berdasarkan taruna_id
	var userID int
	err := m.DB.QueryRow("SELECT user_id FROM taruna WHERE id = ?", p.TarunaID).Scan(&userID)
	if err != nil {
		return fmt.Errorf("taruna not found: %v", err)
	}

	query := `
		INSERT INTO penguji_proposal 
			(user_id, final_proposal_id, ketua_penguji_id, penguji_1_id, penguji_2_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE 
			ketua_penguji_id = VALUES(ketua_penguji_id),
			penguji_1_id = VALUES(penguji_1_id),
			penguji_2_id = VALUES(penguji_2_id),
			updated_at = NOW()
	`

	_, err = m.DB.Exec(query, userID, p.FinalProposalID, p.KetuaID, p.Penguji1ID, p.Penguji2ID)
	return err
}
