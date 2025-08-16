package controllers

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"ta_service/entities"
	"ta_service/utils"
	"time"
)

// Fungsi untuk menampilkan dashboard
func Index(w http.ResponseWriter, r *http.Request) {
	temp, _ := template.ParseFiles("static/dashboard.html")
	temp.Execute(w, nil)
}

func LoginUsers(w http.ResponseWriter, r *http.Request) {
	temp, _ := template.ParseFiles("static/login.html")
	temp.Execute(w, nil)
}

// ADMIN WEB SERVICE
func AdminDashboard(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Serve the admin dashboard HTML file
	http.ServeFile(w, r, "static/admin/admin_dashboard.html")
}

func Calendar(w http.ResponseWriter, r *http.Request) {
	temp, err := template.ParseFiles("static/admin/calendar.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	temp.Execute(w, nil)
}

func ListUser(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Serve the admin dashboard HTML file
	http.ServeFile(w, r, "static/admin/listuser.html")
}

func ListDosen(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Serve the admin dashboard HTML file
	http.ServeFile(w, r, "static/admin/listdosen.html")
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	temp, err := template.ParseFiles("static/admin/adduser.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	temp.Execute(w, nil)
}

func Profile(w http.ResponseWriter, r *http.Request) {
	temp, err := template.ParseFiles("static/admin/profile.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	temp.Execute(w, nil)
}

func EditUser(w http.ResponseWriter, r *http.Request) {
	temp, err := template.ParseFiles("static/admin/edituser.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	temp.Execute(w, nil)
}

// ... existing code ...
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari header / cookie
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		if cookie, err := r.Cookie("token"); err == nil {
			tokenString = cookie.Value
		}
	}

	// Validasi token & role
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	if r.Method == "GET" {
		userID := r.URL.Query().Get("id")
		safeUserID := utils.SanitizeLogInput(userID)

		client := &http.Client{
			Timeout: 10 * time.Second,
		}

		apiURL := "http://104.43.89.154:8081/users/detail?id=" + safeUserID
		log.Printf("Mencoba mengakses API: %s", apiURL)

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			log.Printf("Error membuat request: %v", err)
			http.Error(w, "Gagal membuat request", http.StatusInternalServerError)
			return
		}

		// Tambahkan token ke header
		if !strings.HasPrefix(tokenString, "Bearer ") {
			tokenString = "Bearer " + tokenString
		}
		req.Header.Set("Authorization", tokenString)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error mengakses API: %v", err)
			if strings.Contains(err.Error(), "connection refused") {
				http.Error(w, "API service tidak dapat diakses. Pastikan API service sudah berjalan di port 8081", http.StatusServiceUnavailable)
			} else {
				http.Error(w, "Gagal mengambil data user: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error membaca response: %v", err)
			http.Error(w, "Gagal membaca response dari API", http.StatusInternalServerError)
			return
		}

		// Log respons disanitasi (jika perlu, bisa dipangkas)
		log.Printf("API Response (truncated): %.200s", utils.SanitizeLogInput(string(body)))

		var user entities.User
		if err := json.Unmarshal(body, &user); err != nil {
			log.Printf("Error decode JSON: %v", err)
			http.Error(w, "Gagal memproses data user", http.StatusInternalServerError)
			return
		}

		// Parse dan tampilkan template
		temp, err := template.ParseFiles("static/admin/deleteuser.html")
		if err != nil {
			log.Printf("Error parsing template: %v", err)
			http.Error(w, "Gagal memuat template", http.StatusInternalServerError)
			return
		}

		data := map[string]interface{}{
			"user": user,
		}

		if err := temp.Execute(w, data); err != nil {
			log.Printf("Error executing template: %v", err)
			http.Error(w, "Gagal menampilkan halaman", http.StatusInternalServerError)
			return
		}
	}
}

// Handler untuk halaman ICP admin
func ListICP2(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin ICP HTML file
	http.ServeFile(w, r, "static/admin/icp_admin_3.html")
}

// Handler untuk halaman List Penguji Proposal admin
func ListPenelaahICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/penelaah_icp_admin.html")
}

// Handler untuk halaman Proposal admin
func ListICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/icp_admin.html")
}

// Handler untuk halaman Detail Telaah ICP admin
func DetailTelaahICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/detail_telaah_icp.html")
}

// Handler untuk list Revisi ICP admin
func RevisiICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/revisi_icp_admin.html")
}

// Handler untuk halaman Proposal admin
func ListProposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/proposal_admin.html")
}

// Handler untuk halaman Detail Berkas Proposal admin
func DetailBerkasProposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/detail_berkas_seminar_proposal.html")
}

// Handler untuk halaman List Pembimbing Proposal admin
func ListPembimbingProposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/dosbing_proposal_admin.html")
}

// Handler untuk halaman List Penguji Proposal admin
func ListPengujiProposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/penguji_proposal_admin.html")
}

// Handler untuk list Revisi Proposal admin
func RevisiProposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/revisi_proposal_admin.html")
}

// Handler untuk halaman List Penguji Proposal admin
func ListPengujiLaporan70(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/penguji_laporan70_admin.html")
}

// Handler untuk halaman Proposal admin
func ListLaporan70(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/laporan70_admin.html")
}

// Handler untuk halaman Detail Berkas Proposal admin
func DetailBerkasLaporan70(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/detail_berkas_seminar_laporan70.html")
}

// Handler untuk halaman List Penguji Proposal admin
func ListPengujiLaporan100(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/penguji_laporan100_admin.html")
}

// Handler untuk halaman Proposal admin
func ListLaporan100(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/laporan100_admin.html")
}

// Handler untuk halaman Detail Berkas Proposal admin
func DetailBerkasLaporan100(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/detail_berkas_seminar_laporan100.html")
}

// Handler untuk halaman Detail Berkas Proposal admin
func Repositori(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/repositori_admin.html")
}

// Handler untuk halaman Detail Berkas Proposal admin
func DetailTugasAkhir(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/detail_berkas_tugas_akhir.html")
}

// Handler untuk halaman Detail Berkas Proposal admin
func Notification(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "admin" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the admin Proposal HTML file
	http.ServeFile(w, r, "static/admin/notification.html")
}

// TARUNA WEB SERVICE
// TarunaDashboard menangani tampilan dashboard untuk taruna
func TarunaDashboard(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the taruna dashboard HTML file
	http.ServeFile(w, r, "static/taruna/taruna_dashboard.html")
}

func ICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" { // Ubah dari "admin" menjadi "taruna"
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the ICP HTML file
	http.ServeFile(w, r, "static/taruna/icp.html")
}

func EditICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/taruna/editicp.html")
}

// untuk halaman proposal taruna
func Proposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" { // Ubah dari "admin" menjadi "taruna"
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the Proposal HTML file
	http.ServeFile(w, r, "static/taruna/proposal.html")
}

// untuk halaman laporan 70% taruna
func Laporan70(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" { // Ubah dari "admin" menjadi "taruna"
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the Proposal HTML file
	http.ServeFile(w, r, "static/taruna/laporan70.html")
}

// Handler untuk profile taruna
func ProfileTaruna(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/taruna/profile_taruna.html")
}

// Handler untuk halaman edit profile taruna
func EditProfileTaruna(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/taruna/edituser_taruna.html")
}

// Handler for viewing ICP details for taruna
func ViewICPTaruna(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/taruna/viewicp_taruna.html")
}

// untuk halaman laporan 70% taruna
func Laporan100(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" { // Ubah dari "admin" menjadi "taruna"
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the Proposal HTML file
	http.ServeFile(w, r, "static/taruna/laporan100.html")
}

// Handler for viewing Detail Informasi Notif details for taruna
func DetailInformasiTaruna(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "taruna" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/taruna/detail_informasi.html")
}

// DOSEN WEB SERVICE
// Halaman dashboard dosen
func DosenDashboard(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the dosen dashboard HTML file
	http.ServeFile(w, r, "static/dosen/dosen_dashboard.html")
}

// halaman review icp dosen
func ReviewICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review ICP HTML file
	http.ServeFile(w, r, "static/dosen/bimbingan_icp.html")
}

// Handler untuk penguji ICP
func PengujiICP(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review icp HTML file
	http.ServeFile(w, r, "static/dosen/penguji_icp.html")
}

// Handler untuk profile dosen
func ProfileDosen(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/dosen/profile_dosen.html")
}

// Handler untuk edit profile dosen
func EditProfileDosen(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/dosen/edituser_dosen.html")
}

// Handler for dosen review proposal
func BimbinganProposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review proposal HTML file
	http.ServeFile(w, r, "static/dosen/bimbingan_proposal.html")
}

// Handler untuk penguji proposal
func PengujiProposal(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review proposal HTML file
	http.ServeFile(w, r, "static/dosen/penguji_proposal.html")
}

// Handler for dosen view ICP page
func ViewICPDosen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, "static/dosen/viewicp_dosen.html")
}

// Handler for viewing ICP review details
func ViewICPReviewDosen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, "static/dosen/viewicp_review_dosen.html")
}

// Handler for viewing ICP revision details
func ViewICPRevisiDosen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, "static/dosen/viewicp_revisi_dosen.html")
}

// Handler for dosen review proposal
func BimbinganLaporan70(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review proposal HTML file
	http.ServeFile(w, r, "static/dosen/bimbingan_laporan70.html")
}

// Handler untuk penguji proposal
func PengujiLaporan70(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review proposal HTML file
	http.ServeFile(w, r, "static/dosen/penguji_laporan70.html")
}

// Handler for dosen review proposal
func BimbinganLaporan100(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review proposal HTML file
	http.ServeFile(w, r, "static/dosen/bimbingan_laporan100.html")
}

// Handler untuk penguji proposal
func PengujiLaporan100(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Validasi token dan role
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	// Serve the review proposal HTML file
	http.ServeFile(w, r, "static/dosen/penguji_laporan100.html")
}

// Handler for viewing Detail Informasi Notif details for dosen
func DetailInformasiDosen(w http.ResponseWriter, r *http.Request) {
	// Set header content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Ambil token dari cookie atau header
	var tokenString string
	cookie, err := r.Cookie("token")
	if err == nil {
		tokenString = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.Replace(authHeader, "Bearer ", "", 1)
		}
	}

	// Validasi token
	claims, err := utils.ParseJWT(tokenString)
	if err != nil || strings.ToLower(claims.Role) != "dosen" {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/dosen/detail_informasi.html")
}
