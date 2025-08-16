package entities

type RevisiLaporan70 struct {
	ID              int    `json:"id"`
	UserID          int    `json:"user_id"`
	NamaLengkap     string `json:"nama_lengkap"`
	Jurusan         string `json:"jurusan"`
	Kelas           string `json:"kelas"`
	TopikPenelitian string `json:"topik_penelitian"`
	FilePath        string `json:"file_path"`
	Keterangan      string `json:"keterangan"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}
