package entities

type User struct {
	ID          int    `json:"id"`
	NamaLengkap string `json:"nama_lengkap"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	Password    string `json:"password"`
	Jurusan     string `json:"jurusan"`
	Kelas       string `json:"kelas,omitempty"` // omitempty karena Dosen tidak memiliki kelas
	NPM         *int   `json:"npm,omitempty"`
}
