package entities

type ReviewLaporan70 struct {
	ID              int    `json:"id"`
	Laporan70ID     int    `json:"laporan70_id"`
	DosenID         int    `json:"dosen_id"`
	TarunaID        int    `json:"taruna_id"`
	TopikPenelitian string `json:"topik_penelitian"`
	Keterangan      string `json:"keterangan"`
	FilePath        string `json:"file_path"`
	CycleNumber     int    `json:"cycle_number"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	NamaTaruna      string `json:"nama_taruna"`
	DosenNama       string `json:"dosen_nama"`
}
