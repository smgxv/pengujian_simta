// models/dosbing_model.go
package models

import (
	"database/sql"
	"fmt"
	"user_service/config"
	"user_service/entities"
)

type PengujiLaporan70Model struct {
	DB *sql.DB
}

func NewPengujiLaporan70Model() (*PengujiLaporan70Model, error) {
	db, err := config.ConnectDB()
	if err != nil {
		return nil, err
	}
	return &PengujiLaporan70Model{DB: db}, nil
}

func (m *PengujiLaporan70Model) AssignPengujiLaporan70(p *entities.PengujiLaporan70) error {
	// Ambil user_id berdasarkan taruna_id
	var userID int
	err := m.DB.QueryRow("SELECT user_id FROM taruna WHERE id = ?", p.TarunaID).Scan(&userID)
	if err != nil {
		return fmt.Errorf("taruna not found: %v", err)
	}

	query := `
		INSERT INTO penguji_laporan70
			(user_id, final_laporan70_id, penguji_1_id, penguji_2_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE 
			penguji_1_id = VALUES(penguji_1_id),
			penguji_2_id = VALUES(penguji_2_id),
			updated_at = NOW()
	`

	_, err = m.DB.Exec(query, userID, p.FinalLaporan70ID, p.Penguji1ID, p.Penguji2ID)
	return err
}
