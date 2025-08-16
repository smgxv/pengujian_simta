package models

import (
	"database/sql"
	"errors"
	"ta_service/config"
	"ta_service/entities"
)

type UserModel struct {
	db *sql.DB
}

func NewUserModel() *UserModel {
	conn, err := config.DBConn()

	if err != nil {
		panic(err)
	}

	return &UserModel{
		db: conn,
	}
}

// Ambil data user berdasarkan field name
func (u UserModel) Where(user *entities.User, fieldName, fieldValue string) error {
	// Validasi field name untuk cegah SQL Injection
	validFields := map[string]bool{
		"email":    true,
		"username": true,
	}
	if !validFields[fieldName] {
		return errors.New("invalid field name")
	}

	// Gunakan QueryRow karena hanya satu baris
	query := `
		SELECT id, nama_lengkap, email, username, password, role, jurusan, kelas
		FROM users
		WHERE ` + fieldName + ` = ?
		LIMIT 1
	`

	return u.db.QueryRow(query, fieldValue).Scan(
		&user.ID,
		&user.NamaLengkap,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.Role,
		&user.Jurusan,
		&user.Kelas,
	)
}

// Ambil ID dosen berdasarkan ID user
func (u UserModel) GetDosenIDByUserID(userID int64) (int64, error) {
	var dosenID int64
	err := u.db.QueryRow("SELECT id FROM dosen WHERE user_id = ?", userID).Scan(&dosenID)
	if err != nil {
		return 0, err
	}
	return dosenID, nil
}
