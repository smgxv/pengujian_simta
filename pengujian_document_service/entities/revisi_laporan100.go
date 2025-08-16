package entities

type RevisiLaporan100 struct {
	ID              int    `json:"id"`
	UserID          int    `json:"user_id"`
	NamaLengkap     string `json:"nama_lengkap"`
	Jurusan         string `json:"jurusan"`
	Kelas           string `json:"kelas"`
	TahunAkademik   string `json:"tahun_akademik"`
	TopikPenelitian string `json:"topik_penelitian"`
	AbstrakID       string `json:"abstrak_id"`
	AbstrakEN       string `json:"abstrak_en"`
	KataKunci       string `json:"kata_kunci"`
	LinkRepo        string `json:"link_repo"`
	FilePath        string `json:"file_path"`
	FileProdukPath  string `json:"file_produk_path"`
	FileBapPath     string `json:"file_bap_path"`
	Keterangan      string `json:"keterangan"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}
