package models

import (
	"database/sql"
	"document_service/entities"
	"time"
)

type ProposalModel struct {
	db *sql.DB
}

func NewProposalModel(db *sql.DB) *ProposalModel {
	return &ProposalModel{db: db}
}

func (m *ProposalModel) Create(proposal *entities.Proposal) error {
	query := `
		INSERT INTO proposal (
			user_id, dosen_id, topik_penelitian, keterangan, 
			file_path, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now().Format("2006-01-02 15:04:05")

	_, err := m.db.Exec(
		query,
		proposal.UserID,
		proposal.DosenID,
		proposal.TopikPenelitian,
		proposal.Keterangan,
		proposal.FilePath,
		"pending", // status awal
		now,       // created_at
		now,       // updated_at
	)

	return err
}

func (m *ProposalModel) GetByUserID(userID string) ([]entities.Proposal, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, d.nama_lengkap as dosen_nama
        FROM proposal i
        LEFT JOIN dosen d ON i.dosen_id = d.id
        WHERE i.user_id = ?
    `

	rows, err := m.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proposals []entities.Proposal
	for rows.Next() {
		var proposal entities.Proposal
		err := rows.Scan(
			&proposal.ID,
			&proposal.UserID,
			&proposal.DosenID,
			&proposal.TopikPenelitian,
			&proposal.Keterangan,
			&proposal.FilePath,
			&proposal.Status,
			&proposal.CreatedAt,
			&proposal.UpdatedAt,
			&proposal.DosenNama, // Tambahkan field ini di struct ICP
		)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, proposal)
	}
	return proposals, nil
}

func (m *ProposalModel) GetByID(id string) (*entities.Proposal, error) {
	query := `
        SELECT i.*, d.nama_lengkap as dosen_nama 
        FROM proposal i 
        LEFT JOIN dosen d ON i.dosen_id = d.id 
        WHERE i.id = ?
    `

	var proposal entities.Proposal
	err := m.db.QueryRow(query, id).Scan(
		&proposal.ID, &proposal.UserID, &proposal.DosenID, &proposal.TopikPenelitian,
		&proposal.Keterangan, &proposal.FilePath, &proposal.Status, &proposal.CreatedAt,
		&proposal.UpdatedAt, &proposal.DosenNama,
	)
	if err != nil {
		return nil, err
	}
	return &proposal, nil
}

func (m *ProposalModel) Update(proposal *entities.Proposal) error {
	query := `
        UPDATE proposal 
        SET dosen_id = ?, topik_penelitian = ?, keterangan = ?, 
            file_path = ?, updated_at = NOW()
        WHERE id = ?
    `

	_, err := m.db.Exec(query,
		proposal.DosenID,
		proposal.TopikPenelitian,
		proposal.Keterangan,
		proposal.FilePath,
		proposal.ID,
	)
	return err
}

func (m *ProposalModel) GetByDosenID(dosenID string) ([]entities.Proposal, error) {
	query := `
        SELECT 
            i.id, i.user_id, i.dosen_id, i.topik_penelitian,
            i.keterangan, i.file_path, i.status, i.created_at,
            i.updated_at, t.nama_lengkap as nama_taruna, t.kelas
        FROM proposal i
        LEFT JOIN taruna t ON i.user_id = t.user_id
        WHERE i.dosen_id = ?
    `

	rows, err := m.db.Query(query, dosenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var proposals []entities.Proposal
	for rows.Next() {
		var proposal entities.Proposal
		var namaTaruna sql.NullString
		var kelas sql.NullString
		err := rows.Scan(
			&proposal.ID,
			&proposal.UserID,
			&proposal.DosenID,
			&proposal.TopikPenelitian,
			&proposal.Keterangan,
			&proposal.FilePath,
			&proposal.Status,
			&proposal.CreatedAt,
			&proposal.UpdatedAt,
			&namaTaruna,
			&kelas,
		)
		if err != nil {
			return nil, err
		}
		if namaTaruna.Valid {
			proposal.NamaTaruna = namaTaruna.String
		} else {
			proposal.NamaTaruna = ""
		}
		if kelas.Valid {
			proposal.Kelas = kelas.String
		} else {
			proposal.Kelas = ""
		}
		proposals = append(proposals, proposal)
	}
	return proposals, nil
}
