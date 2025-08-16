package entities

import "encoding/json"

type FinalLaporan70 struct {
	ID                int    `json:"id"`
	UserID            int    `json:"user_id"`
	NamaLengkap       string `json:"nama_lengkap"`
	Jurusan           string `json:"jurusan"`
	Kelas             string `json:"kelas"`
	TopikPenelitian   string `json:"topik_penelitian"`
	FilePath          string `json:"file_path"`
	FilePendukungPath string `json:"file_pendukung_path"`
	FormBimbinganPath string `json:"form_bimbingan_path"`
	Keterangan        string `json:"keterangan"`
	Status            string `json:"status"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// Helper opsional
func (f *FinalLaporan70) GetLaporan70SupportingFiles() ([]string, error) {
	var paths []string
	if f.FilePendukungPath == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(f.FilePendukungPath), &paths); err != nil {
		return nil, err
	}
	return paths, nil
}

func (f *FinalLaporan70) SetLaporan70SupportingFiles(paths []string) error {
	b, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	f.FilePendukungPath = string(b)
	return nil
}
