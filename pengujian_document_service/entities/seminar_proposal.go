package entities

import "time"

type SeminarProposal struct {
	ID               int       `json:"id"`
	UserID           int       `json:"user_id"`
	TopikPenelitian  string    `json:"topik_penelitian"`
	FileProposalPath string    `json:"file_proposal_path"`
	KetuaPengujiID   int       `json:"ketua_penguji_id"`
	Penguji1ID       int       `json:"penguji1_id"`
	Penguji2ID       int       `json:"penguji2_id"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}
