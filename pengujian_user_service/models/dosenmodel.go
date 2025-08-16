package models

import (
	"database/sql"
	"user_service/config"
	"user_service/entities"
)

type DosenModel struct {
	db *sql.DB
}

func NewDosenModel() (*DosenModel, error) {
	db, err := config.ConnectDB()
	if err != nil {
		return nil, err
	}
	return &DosenModel{db: db}, nil
}

func (d *DosenModel) CreateDosen(userID int, namaLengkap, jurusan string) error {
	_, err := d.db.Exec("INSERT INTO dosen (id, nama_lengkap, jurusan) VALUES (?, ?, ?)",
		userID, namaLengkap, jurusan)
	return err
}

func (d *DosenModel) GetAllDosen() ([]map[string]interface{}, error) {
	rows, err := d.db.Query(`
        SELECT d.id, d.user_id, d.nama_lengkap, d.jurusan 
        FROM dosen d
        JOIN users u ON d.user_id = u.id
        WHERE u.role = 'Dosen'
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dosens []map[string]interface{}
	for rows.Next() {
		var id, userID int
		var namaLengkap, jurusan string

		err := rows.Scan(&id, &userID, &namaLengkap, &jurusan)
		if err != nil {
			return nil, err
		}

		dosen := map[string]interface{}{
			"id":           id,
			"user_id":      userID,
			"nama_lengkap": namaLengkap,
			"jurusan":      jurusan,
		}
		dosens = append(dosens, dosen)
	}

	return dosens, nil
}

// Update password dosen berdasarkan user_id
func (d *DosenModel) UpdateDosenPassword(userID int, hashedPassword string) error {
	_, err := d.db.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userID)
	return err
}

// Update data dosen
func (d *DosenModel) UpdateDosen(userID int, namaLengkap, jurusan string) error {
	_, err := d.db.Exec("UPDATE dosen SET nama_lengkap = ?, jurusan = ? WHERE user_id = ?",
		namaLengkap, jurusan, userID)
	return err
}

// Get dosen by user_id
func (d *DosenModel) GetDosenByUserID(userID int) (*entities.Dosen, error) {
	var dosen entities.Dosen
	err := d.db.QueryRow("SELECT id, user_id, nama_lengkap, jurusan FROM dosen WHERE user_id = ?", userID).
		Scan(&dosen.ID, &dosen.UserID, &dosen.NamaLengkap, &dosen.Jurusan)
	if err != nil {
		return nil, err
	}
	return &dosen, nil
}
