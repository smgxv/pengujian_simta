package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

func InsertSeminarLaporan100(db *sql.DB, laporan100 *entities.SeminarLaporan100) error {
	query := `
		INSERT INTO seminar_laporan100 (
			user_id, topik_penelitian, file_laporan100_path,
			ketua_penguji_id, penguji1_id, penguji2_id,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	_, err := db.Exec(query,
		laporan100.UserID,
		laporan100.TopikPenelitian,
		laporan100.FileLaporan100Path,
		laporan100.KetuaPengujiID,
		laporan100.Penguji1ID,
		laporan100.Penguji2ID,
		now,
		now,
	)

	return err
}

func GetSeminarLaporan100ByUserID(db *sql.DB, userID int) ([]entities.SeminarLaporan100, error) {
	query := `
		SELECT id, user_id, topik_penelitian, file_laporan100_path,
		       ketua_penguji_id, penguji1_id, penguji2_id,
		       created_at, updated_at
		FROM seminar_laporan100
		WHERE user_id = ?
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var laporan100s []entities.SeminarLaporan100
	for rows.Next() {
		var laporan100 entities.SeminarLaporan100
		err := rows.Scan(
			&laporan100.ID,
			&laporan100.UserID,
			&laporan100.TopikPenelitian,
			&laporan100.FileLaporan100Path,
			&laporan100.KetuaPengujiID,
			&laporan100.Penguji1ID,
			&laporan100.Penguji2ID,
			&laporan100.CreatedAt,
			&laporan100.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		laporan100s = append(laporan100s, laporan100)
	}

	return laporan100s, nil
}
