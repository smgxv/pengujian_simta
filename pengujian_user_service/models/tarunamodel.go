package models

import (
	"database/sql"
	"user_service/config"
)

type TarunaModel struct {
	db *sql.DB
}

func NewTarunaModel() (*TarunaModel, error) {
	db, err := config.ConnectDB()
	if err != nil {
		return nil, err
	}
	return &TarunaModel{db: db}, nil
}

func (d *TarunaModel) CreateTaruna(userID int, namaLengkap, email, jurusan, kelas string, npm *int) error {
	_, err := d.db.Exec("INSERT INTO taruna (user_id, nama_lengkap, email, jurusan, kelas, npm) VALUES (?, ?, ?, ?, ?, ?)",
		userID, namaLengkap, email, jurusan, kelas, npm)
	return err
}

func (d *TarunaModel) GetAllTaruna() ([]map[string]interface{}, error) {
	rows, err := d.db.Query(`
        SELECT t.id, t.user_id, t.nama_lengkap, t.jurusan, t.kelas, t.npm
        FROM taruna t
        JOIN users u ON t.user_id = u.id
        WHERE u.role = 'Taruna'
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tarunas []map[string]interface{}
	for rows.Next() {
		var id, userID int
		var namaLengkap, jurusan, kelas, npm string

		err := rows.Scan(&id, &userID, &namaLengkap, &jurusan, &kelas, &npm)
		if err != nil {
			return nil, err
		}

		taruna := map[string]interface{}{
			"id":           id,
			"user_id":      userID,
			"nama_lengkap": namaLengkap,
			"jurusan":      jurusan,
			"kelas":        kelas,
			"npm":          npm,
		}
		tarunas = append(tarunas, taruna)
	}

	return tarunas, nil
}

// Update password taruna berdasarkan user_id
func (d *TarunaModel) UpdateTarunaPassword(userID int, hashedPassword string) error {
	_, err := d.db.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userID)
	return err
}

func (m *TarunaModel) GetTarunaByUserID(userID int) (map[string]interface{}, error) {
	row := m.db.QueryRow("SELECT id, user_id, nama_lengkap, email, jurusan, kelas FROM taruna WHERE user_id = ?", userID)
	var id, uid int
	var nama, email, jurusan, kelas string
	err := row.Scan(&id, &uid, &nama, &email, &jurusan, &kelas)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"id":           id,
		"user_id":      uid,
		"nama_lengkap": nama,
		"email":        email,
		"jurusan":      jurusan,
		"kelas":        kelas,
	}, nil
}

func (m *TarunaModel) GetDB() *sql.DB {
	return m.db
}
