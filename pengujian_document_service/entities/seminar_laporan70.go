package entities

import "time"

type SeminarLaporan70 struct {
	ID                int       `json:"id"`
	UserID            int       `json:"user_id"`
	TopikPenelitian   string    `json:"topik_penelitian"`
	FileLaporan70Path string    `json:"file_laporan70_path"`
	Penguji1ID        int       `json:"penguji1_id"`
	Penguji2ID        int       `json:"penguji2_id"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}
