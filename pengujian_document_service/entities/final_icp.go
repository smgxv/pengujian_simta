package entities

import "encoding/json"

type FinalICP struct {
	ID                int    `json:"id"`
	UserID            int    `json:"user_id"`
	NamaLengkap       string `json:"nama_lengkap"`
	Jurusan           string `json:"jurusan"`
	Kelas             string `json:"kelas"`
	TopikPenelitian   string `json:"topik_penelitian"`
	FilePath          string `json:"file_path"`           // path file final
	FilePendukungPath string `json:"file_pendukung_path"` // JSON array string berisi path file pendukung
	Keterangan        string `json:"keterangan"`
	Status            string `json:"status"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// Helper opsional
func (f *FinalICP) GetSupportingFiles() ([]string, error) {
	var paths []string
	if f.FilePendukungPath == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(f.FilePendukungPath), &paths); err != nil {
		return nil, err
	}
	return paths, nil
}

func (f *FinalICP) SetSupportingFiles(paths []string) error {
	b, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	f.FilePendukungPath = string(b)
	return nil
}
