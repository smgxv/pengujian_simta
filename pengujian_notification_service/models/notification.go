package models

import "time"

type Notification struct {
	ID        string
	Judul     string
	Deskripsi string
	Target    string
	FileURLs  string
	CreatedAt time.Time
}
