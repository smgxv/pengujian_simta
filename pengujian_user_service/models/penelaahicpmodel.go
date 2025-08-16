// models/dosbing_model.go
package models

import (
	"database/sql"
	"fmt"
	"user_service/config"
	"user_service/entities"
)

type PenelaahICPModel struct {
	DB *sql.DB
}

func NewPenelaahICPModel() (*PenelaahICPModel, error) {
	db, err := config.ConnectDB()
	if err != nil {
		return nil, err
	}
	return &PenelaahICPModel{DB: db}, nil
}

func (m *PenelaahICPModel) AssignPenelaahICP(p *entities.PenelaahICP) error {
	// Ambil user_id berdasarkan taruna_id
	var userID int
	err := m.DB.QueryRow("SELECT user_id FROM taruna WHERE id = ?", p.TarunaID).Scan(&userID)
	if err != nil {
		return fmt.Errorf("taruna not found: %v", err)
	}

	query := `
		INSERT INTO penelaah_icp
			(user_id, final_icp_id, penelaah_1_id, penelaah_2_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE 
			penelaah_1_id = VALUES(penelaah_1_id),
			penelaah_2_id = VALUES(penelaah_2_id),
			updated_at = NOW()
	`

	_, err = m.DB.Exec(query, userID, p.FinalICPID, p.Penelaah1ID, p.Penelaah2ID)
	return err
}
