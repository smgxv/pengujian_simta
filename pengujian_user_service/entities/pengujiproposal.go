// entities/pengujiproposal.go
package entities

type PengujiProposal struct {
	TarunaID        int `json:"taruna_id"`
	FinalProposalID int `json:"final_proposal_id"`
	KetuaID         int `json:"ketua_id"`
	Penguji1ID      int `json:"penguji_1_id"`
	Penguji2ID      int `json:"penguji_2_id"`
}
