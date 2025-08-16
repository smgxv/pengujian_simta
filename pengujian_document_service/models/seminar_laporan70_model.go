package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

func InsertSeminarLaporan70(db *sql.DB, laporan70 *entities.SeminarLaporan70) error {
	query := `
		INSERT INTO seminar_laporan70 (
			user_id, topik_penelitian, file_laporan70_path,
			penguji1_id, penguji2_id,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	_, err := db.Exec(query,
		laporan70.UserID,
		laporan70.TopikPenelitian,
		laporan70.FileLaporan70Path,
		laporan70.Penguji1ID,
		laporan70.Penguji2ID,
		now,
		now,
	)

	return err
}

func GetSeminarLaporan70ByUserID(db *sql.DB, userID int) ([]entities.SeminarLaporan70, error) {
	query := `
		SELECT id, user_id, topik_penelitian, file_laporan70_path,
		       penguji1_id, penguji2_id,
		       created_at, updated_at
		FROM seminar_laporan70
		WHERE user_id = ?
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var laporan70s []entities.SeminarLaporan70
	for rows.Next() {
		var laporan70 entities.SeminarLaporan70
		err := rows.Scan(
			&laporan70.ID,
			&laporan70.UserID,
			&laporan70.TopikPenelitian,
			&laporan70.FileLaporan70Path,
			&laporan70.Penguji1ID,
			&laporan70.Penguji2ID,
			&laporan70.CreatedAt,
			&laporan70.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		laporan70s = append(laporan70s, laporan70)
	}

	return laporan70s, nil
}
