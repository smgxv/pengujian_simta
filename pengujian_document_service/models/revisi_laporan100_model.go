package models

import (
	"database/sql"
	"document_service/entities"
)

type RevisiLaporan100Model struct {
	db *sql.DB
}

func NewRevisiLaporan100Model(db *sql.DB) *RevisiLaporan100Model {
	return &RevisiLaporan100Model{
		db: db,
	}
}

func (m *RevisiLaporan100Model) Create(revisi *entities.RevisiLaporan100) error {
	query := `
		INSERT INTO revisi_laporan100 (
			user_id, nama_lengkap, jurusan, kelas, tahun_akademik,
			topik_penelitian, abstrak_id, abstrak_en, kata_kunci, link_repo,
			file_path, file_produk_path, file_bap_path,
			keterangan, status
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := m.db.Exec(query,
		revisi.UserID, revisi.NamaLengkap, revisi.Jurusan, revisi.Kelas, revisi.TahunAkademik,
		revisi.TopikPenelitian, revisi.AbstrakID, revisi.AbstrakEN, revisi.KataKunci, revisi.LinkRepo,
		revisi.FilePath, revisi.FileProdukPath, revisi.FileBapPath,
		revisi.Keterangan, "pending",
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	revisi.ID = int(id)
	return nil
}

func (m *RevisiLaporan100Model) GetByUserID(userID string) ([]entities.RevisiLaporan100, error) {
	query := `
		SELECT 
			id, user_id, nama_lengkap, jurusan, kelas, tahun_akademik,
			topik_penelitian, abstrak_id, abstrak_en, kata_kunci, link_repo,
			file_path, file_produk_path, file_bap_path,
			keterangan, status, created_at, updated_at
		FROM revisi_laporan100 
		WHERE user_id = ?
		ORDER BY created_at DESC`

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []entities.RevisiLaporan100
	for rows.Next() {
		var r entities.RevisiLaporan100

		// untuk kolom yang bisa NULL
		var linkRepo, fileProdukPath, fileBapPath, keterangan sql.NullString

		err := rows.Scan(
			&r.ID, &r.UserID, &r.NamaLengkap, &r.Jurusan, &r.Kelas, &r.TahunAkademik,
			&r.TopikPenelitian, &r.AbstrakID, &r.AbstrakEN, &r.KataKunci, &linkRepo,
			&r.FilePath, &fileProdukPath, &fileBapPath,
			&keterangan, &r.Status, &r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// konversi nilai NULL ke string kosong
		r.LinkRepo = ""
		if linkRepo.Valid {
			r.LinkRepo = linkRepo.String
		}

		r.FileProdukPath = ""
		if fileProdukPath.Valid {
			r.FileProdukPath = fileProdukPath.String
		}

		r.FileBapPath = ""
		if fileBapPath.Valid {
			r.FileBapPath = fileBapPath.String
		}

		r.Keterangan = ""
		if keterangan.Valid {
			r.Keterangan = keterangan.String
		}

		results = append(results, r)
	}
	return results, nil
}
