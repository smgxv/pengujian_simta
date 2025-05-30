// models/dosbing_model.go
package models

import (
	"database/sql"
	"user_service/config"
	"user_service/entities"
)

type DosbingModel struct {
	DB *sql.DB
}

func NewDosbingModel() (*DosbingModel, error) {
	db, err := config.ConnectDB()
	if err != nil {
		return nil, err
	}
	return &DosbingModel{DB: db}, nil
}

func (m *DosbingModel) AssignPembimbing(dp *entities.DosbingProposal) error {
	query := `
		INSERT INTO dosbing_proposal (user_id, dosen_id, tanggal_ditetapkan, status)
		VALUES (?, ?, CURDATE(), ?)
		ON DUPLICATE KEY UPDATE 
			dosen_id = VALUES(dosen_id),
			tanggal_ditetapkan = CURDATE(),
			status = VALUES(status)
	`
	status := dp.Status
	if status == "" {
		status = "aktif"
	}

	_, err := m.DB.Exec(query, dp.UserID, dp.DosenID, status)
	return err
}
