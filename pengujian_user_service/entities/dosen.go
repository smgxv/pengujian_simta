package entities

type Dosen struct {
	ID          int    `json:"id"`
	UserID      int    `json:"user_id"`
	NamaLengkap string `json:"nama_lengkap"`
	Jurusan     string `json:"jurusan"`
}
