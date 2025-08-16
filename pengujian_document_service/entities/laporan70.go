package entities

type Laporan70 struct {
	ID              int    `json:"id"`
	UserID          int    `json:"user_id"`
	DosenID         int    `json:"dosen_id"`
	TopikPenelitian string `json:"topik_penelitian"`
	Keterangan      string `json:"keterangan"`
	FilePath        string `json:"file_path"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	DosenNama       string `json:"dosen_nama"`
	NamaTaruna      string `json:"nama_taruna"`
	Kelas           string `json:"kelas"`
}
