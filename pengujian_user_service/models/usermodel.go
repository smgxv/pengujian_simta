package models

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"user_service/config"
	"user_service/entities"
)

type UserModel struct {
	db *sql.DB
}

func NewUserModel() (*UserModel, error) {
	db, err := config.ConnectDB()
	if err != nil {
		return nil, err
	}
	return &UserModel{db: db}, nil
}

func (u UserModel) Where(user *entities.User, fieldName, fieldValue string) error {
	// Whitelist kolom agar aman dari SQL injection pada fieldName
	allowed := map[string]bool{"email": true, "username": true, "id": true}
	if !allowed[strings.ToLower(fieldName)] {
		return fmt.Errorf("field tidak diizinkan")
	}

	row, err := u.db.Query(
		"SELECT id, nama_lengkap, email, username, password, role, jurusan, kelas, npm FROM users WHERE "+fieldName+" = ? LIMIT 1",
		fieldValue,
	)
	if err != nil {
		return err
	}
	defer row.Close()

	var jurusan sql.NullString
	var kelas sql.NullString
	var npm sql.NullInt64

	if row.Next() {
		if err := row.Scan(&user.ID, &user.NamaLengkap, &user.Email, &user.Username,
			&user.Password, &user.Role, &jurusan, &kelas, &npm); err != nil {
			return err
		}
		if jurusan.Valid {
			user.Jurusan = jurusan.String
		} else {
			user.Jurusan = ""
		}
		if kelas.Valid {
			user.Kelas = kelas.String
		} else {
			user.Kelas = ""
		}
		if npm.Valid {
			v := int(npm.Int64)
			user.NPM = &v
		} else {
			user.NPM = nil
		}
	}
	return nil
}

func (m *UserModel) FindAll() ([]entities.User, error) {
	rows, err := m.db.Query(`
        SELECT id, nama_lengkap, username, email, role, jurusan, kelas, npm
        FROM users
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []entities.User
	for rows.Next() {
		var user entities.User
		var jurusan, kelas sql.NullString
		var npm sql.NullInt64

		err := rows.Scan(
			&user.ID,
			&user.NamaLengkap,
			&user.Username,
			&user.Email,
			&user.Role,
			&jurusan,
			&kelas,
			&npm,
		)
		if err != nil {
			return nil, err
		}

		// Handle jurusan
		if jurusan.Valid {
			user.Jurusan = jurusan.String
		} else {
			user.Jurusan = ""
		}

		// Handle kelas
		if kelas.Valid {
			user.Kelas = kelas.String
		} else {
			user.Kelas = ""
		}

		// Handle npm
		if npm.Valid {
			npmVal := int(npm.Int64)
			user.NPM = &npmVal
		} else {
			user.NPM = nil
		}

		users = append(users, user)
	}

	return users, nil
}

func (u UserModel) CreateUser(fullName, email, username, role, password, jurusan, kelas, npm string) (int64, error) {
	// Mulai transaksi
	tx, err := u.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("error memulai transaksi: %v", err)
	}

	// Siapkan nilai NULL untuk field opsional (taruna only)
	var kelasVal, npmVal, jurusanVal interface{}
	if strings.ToLower(role) == "taruna" {
		if jurusan == "" || kelas == "" || npm == "" {
			tx.Rollback()
			return 0, fmt.Errorf("taruna wajib mengisi jurusan, kelas, dan NPM")
		}
		jurusanVal = jurusan
		kelasVal = kelas
		npmVal = npm
	} else if strings.ToLower(role) == "dosen" {
		if jurusan == "" {
			tx.Rollback()
			return 0, fmt.Errorf("dosen wajib mengisi jurusan")
		}
		jurusanVal = jurusan
		kelasVal = nil
		npmVal = nil
	} else { // admin
		jurusanVal = nil
		kelasVal = nil
		npmVal = nil
	}

	// Validasi tambahan untuk dosen
	if strings.ToLower(role) == "dosen" && jurusan == "" {
		tx.Rollback()
		return 0, fmt.Errorf("dosen wajib mengisi jurusan")
	}

	// Insert ke tabel users
	result, err := tx.Exec(`
		INSERT INTO users (nama_lengkap, email, username, role, password, jurusan, kelas, npm) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		fullName, email, username, role, password, jurusanVal, kelasVal, npmVal)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("error inserting user: %v", err)
	}

	// Ambil user_id
	userID, err := result.LastInsertId()
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("error getting last insert ID: %v", err)
	}

	// Insert ke tabel sesuai role
	switch strings.ToLower(role) {
	case "dosen":
		log.Printf("Insert ke dosen: user_id=%d, nama=%s, email=%s, jurusan=%s", userID, fullName, email, jurusan)
		_, err = tx.Exec(`
			INSERT INTO dosen (user_id, nama_lengkap, email, jurusan)
			VALUES (?, ?, ?, ?)`,
			userID, fullName, email, jurusan)
		if err != nil {
			log.Printf("Insert ke dosen gagal! userID=%d, err=%v", userID, err)
			tx.Rollback()
			return 0, fmt.Errorf("error inserting dosen: %v", err)
		}

	case "taruna":
		log.Printf("Insert ke taruna: user_id=%d, nama=%s, email=%s, jurusan=%s, kelas=%s, npm=%s",
			userID, fullName, email, jurusan, kelas, npm)
		_, err = tx.Exec(`
			INSERT INTO taruna (user_id, nama_lengkap, email, jurusan, kelas, npm)
			VALUES (?, ?, ?, ?, ?, ?)`,
			userID, fullName, email, jurusan, kelas, npm)
		if err != nil {
			tx.Rollback()
			return 0, fmt.Errorf("error inserting taruna: %v", err)
		}

	case "admin":
		log.Printf("Admin berhasil dibuat: user_id=%d, email=%s", userID, email)
		// Tidak perlu insert tambahan
	}

	// Commit
	if err = tx.Commit(); err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("error committing transaction: %v", err)
	}

	return userID, nil
}

func (u UserModel) UpdateUser(userID int, fullName, email, username, role, jurusan, kelas string, npm *int, hashedPassword []byte) error {
	role = strings.ToLower(role)

	tx, err := u.db.Begin()
	if err != nil {
		return fmt.Errorf("error memulai transaksi: %v", err)
	}

	var oldRole string
	err = tx.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&oldRole)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error mendapatkan role lama: %v", err)
	}
	oldRole = strings.ToLower(oldRole)

	// ================================
	// Update tabel users
	// ================================
	switch role {
	case "taruna":
		if len(hashedPassword) > 0 {
			_, err = tx.Exec(`
				UPDATE users 
				SET nama_lengkap = ?, email = ?, username = ?, role = ?, jurusan = ?, kelas = ?, npm = ?, password = ?
				WHERE id = ?`,
				fullName, email, username, role, jurusan, kelas, npm, hashedPassword, userID)
		} else {
			_, err = tx.Exec(`
				UPDATE users 
				SET nama_lengkap = ?, email = ?, username = ?, role = ?, jurusan = ?, kelas = ?, npm = ?
				WHERE id = ?`,
				fullName, email, username, role, jurusan, kelas, npm, userID)
		}

	case "dosen", "admin":
		if len(hashedPassword) > 0 {
			_, err = tx.Exec(`
				UPDATE users 
				SET nama_lengkap = ?, email = ?, username = ?, role = ?, jurusan = ?, password = ?
				WHERE id = ?`,
				fullName, email, username, role, jurusan, hashedPassword, userID)
		} else {
			_, err = tx.Exec(`
				UPDATE users 
				SET nama_lengkap = ?, email = ?, username = ?, role = ?, jurusan = ?
				WHERE id = ?`,
				fullName, email, username, role, jurusan, userID)
		}

	default:
		tx.Rollback()
		return fmt.Errorf("role tidak dikenal: %v", role)
	}

	if err != nil {
		tx.Rollback()
		return fmt.Errorf("error updating user: %v", err)
	}

	// ================================
	// Bagian ini TIDAK diubah
	// ================================
	if oldRole != role {
		switch oldRole {
		case "dosen":
			_, err = tx.Exec("DELETE FROM dosen WHERE user_id = ?", userID)
		case "taruna":
			_, err = tx.Exec("DELETE FROM taruna WHERE user_id = ?", userID)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error menghapus data role lama: %v", err)
		}

		switch role {
		case "dosen":
			_, err = tx.Exec("INSERT INTO dosen (user_id, nama_lengkap, email, jurusan) VALUES (?, ?, ?, ?)",
				userID, fullName, email, jurusan)
		case "taruna":
			_, err = tx.Exec("INSERT INTO taruna (user_id, nama_lengkap, email, jurusan, kelas, npm) VALUES (?, ?, ?, ?, ?, ?)",
				userID, fullName, email, jurusan, kelas, npm)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error menambah data role baru: %v", err)
		}
	} else {
		switch role {
		case "dosen":
			_, err = tx.Exec("UPDATE dosen SET nama_lengkap = ?, email = ?, jurusan = ? WHERE user_id = ?",
				fullName, email, jurusan, userID)
		case "taruna":
			_, err = tx.Exec("UPDATE taruna SET nama_lengkap = ?, email = ?, jurusan = ?, kelas = ?, npm = ? WHERE user_id = ?",
				fullName, email, jurusan, kelas, npm, userID)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("error mengupdate data role: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return fmt.Errorf("error committing transaction: %v", err)
	}

	return nil
}

func (u UserModel) GetUserByID(userID int) (*entities.User, error) {
	var (
		jurusan sql.NullString
		kelas   sql.NullString
		npm     sql.NullInt64
	)
	user := &entities.User{}
	err := u.db.QueryRow(`
		SELECT id, nama_lengkap, email, username, role, jurusan, kelas, npm
		FROM users WHERE id = ?`, userID).
		Scan(&user.ID, &user.NamaLengkap, &user.Email, &user.Username,
			&user.Role, &jurusan, &kelas, &npm)
	if err != nil {
		return nil, err
	}
	if jurusan.Valid {
		user.Jurusan = jurusan.String
	} else {
		user.Jurusan = ""
	}
	if kelas.Valid {
		user.Kelas = kelas.String
	} else {
		user.Kelas = ""
	}
	if npm.Valid {
		v := int(npm.Int64)
		user.NPM = &v
	} else {
		user.NPM = nil
	}
	return user, nil
}

func (u UserModel) DeleteUser(userID int) error {
	_, err := u.db.Exec("DELETE FROM users WHERE id = ?", userID)
	return err
}
