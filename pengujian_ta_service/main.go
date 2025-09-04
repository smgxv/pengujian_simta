package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"ta_service/controllers"
	"ta_service/handlers"

	"github.com/gorilla/mux"
)

// kunci context utk nonce
type ctxKey string

const cspNonceKey ctxKey = "csp-nonce"

// generator nonce per-request
func genNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ganti ini sesuai kebutuhan Anda:
var (
	// asal host aplikasi web Anda (UI)
	selfOrigin = "http://104.43.89.154:8085"

	// daftar CDN yang benar-benar digunakan (hapus yang tidak dipakai)
	allowedCDN = []string{
		"https://cdn.jsdelivr.net", // contoh: Bootstrap/JS libs
		// "https://cdnjs.cloudflare.com",
		// "https://unpkg.com",
		// "https://fonts.googleapis.com",
		// "https://fonts.gstatic.com",
	}

	// daftar origin microservice/API yang di-call via fetch/XHR/WebSocket
	// tambahkan semua host:port yang relevan (tanpa wildcard)
	backendOrigins = []string{
		"http://104.43.89.154:8085", // jika API di host yg sama
		// "http://104.43.89.154:8081",
		// "http://104.43.89.154:8082",
	}
)

// middleware CSP
// middleware CSP
func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := genNonce()
		if err != nil {
			http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
			return
		}

		// gabung origin yg diizinkan
		cdn := strings.Join(allowedCDN, " ")
		backends := strings.Join(backendOrigins, " ")

		// --- KEBIJAKAN CSP ---
		csp := fmt.Sprintf(
			"script-src 'self' 'nonce-%s' 'strict-dynamic' %s; "+
				"style-src 'self' 'nonce-%s' %s; "+
				"img-src 'self' data: %s; "+
				"font-src 'self' %s; "+
				"connect-src 'self' %s; "+
				"base-uri 'self'; "+
				"frame-ancestors 'none'; "+
				"object-src 'none'; "+
				"form-action 'self'; "+
				"upgrade-insecure-requests",
			nonce, cdn,
			nonce, cdn,
			cdn,
			cdn,
			backends,
		)

		// set header
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// teruskan nonce ke context utk template
		ctx := context.WithValue(r.Context(), cspNonceKey, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ✅ Middleware CORS global
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://104.43.89.154:8085")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	router := mux.NewRouter()

	// Urutan middleware
	// urutan penting: CORS dulu, lalu CSP
	router.Use(corsMiddleware)
	router.Use(cspMiddleware)

	// ✅ STATIC FILES
	staticDirs := map[string]string{
		"/style/":          "static/style/",
		"/admin/src/":      "static/admin/src/",
		"/admin/vendors/":  "static/admin/vendors/",
		"/taruna/src/":     "static/taruna/src/",
		"/taruna/vendors/": "static/taruna/vendors/",
		"/dosen/src/":      "static/dosen/src/",
		"/dosen/vendors/":  "static/dosen/vendors/",
	}

	for prefix, path := range staticDirs {
		router.PathPrefix(prefix).Handler(http.StripPrefix(prefix, http.FileServer(http.Dir(path))))
	}

	// ✅ PUBLIC ROUTES
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loginusers", http.StatusSeeOther)
	}).Methods("GET")

	router.HandleFunc("/loginusers", controllers.LoginUsers).Methods("GET")
	router.HandleFunc("/login", handlers.LoginHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/logout", handlers.LogoutHandler).Methods("POST", "OPTIONS")

	// ✅ WEB ENDPOINTS
	router.HandleFunc("/dashboard", controllers.Index)

	// ✅ ADMIN ROUTES
	admin := router.PathPrefix("/admin").Subrouter()
	// admin.Use(middleware.RoleRedirectMiddleware)

	admin.HandleFunc("/dashboard", controllers.AdminDashboard).Methods("GET", "OPTIONS")
	admin.HandleFunc("/calendar", controllers.Calendar).Methods("GET")
	admin.HandleFunc("/listuser", controllers.ListUser).Methods("GET")
	admin.HandleFunc("/adduser", controllers.AddUser).Methods("GET", "POST")
	admin.HandleFunc("/profile", controllers.Profile).Methods("GET")
	admin.HandleFunc("/edituser", controllers.EditUser).Methods("GET")
	admin.HandleFunc("/deleteuser", controllers.DeleteUser).Methods("GET", "POST")
	admin.HandleFunc("/listdosen", controllers.ListDosen).Methods("GET")
	admin.HandleFunc("/listicp", controllers.ListICP).Methods("GET", "OPTIONS")
	admin.HandleFunc("/penelaah_icp", controllers.ListPenelaahICP).Methods("GET", "OPTIONS")
	admin.HandleFunc("/list_icp", controllers.ListICP).Methods("GET", "OPTIONS")
	admin.HandleFunc("/revisi_icp", controllers.RevisiICP).Methods("GET", "OPTIONS")
	admin.HandleFunc("/listproposal", controllers.ListProposal).Methods("GET", "OPTIONS")
	admin.HandleFunc("/detail_berkas_seminar_proposal", controllers.DetailBerkasProposal).Methods("GET", "OPTIONS")
	admin.HandleFunc("/detail_telaah_icp", controllers.DetailTelaahICP).Methods("GET", "OPTIONS")
	admin.HandleFunc("/dosbing_proposal", controllers.ListPembimbingProposal).Methods("GET", "OPTIONS")
	admin.HandleFunc("/penguji_proposal", controllers.ListPengujiProposal).Methods("GET", "OPTIONS")
	admin.HandleFunc("/revisi_proposal", controllers.RevisiProposal).Methods("GET", "OPTIONS")
	admin.HandleFunc("/penguji_laporan70", controllers.ListPengujiLaporan70).Methods("GET", "OPTIONS")
	admin.HandleFunc("/listlaporan70", controllers.ListLaporan70).Methods("GET", "OPTIONS")
	admin.HandleFunc("/detail_berkas_seminar_laporan70", controllers.DetailBerkasLaporan70).Methods("GET", "OPTIONS")
	admin.HandleFunc("/penguji_laporan100", controllers.ListPengujiLaporan100).Methods("GET", "OPTIONS")
	admin.HandleFunc("/listlaporan100", controllers.ListLaporan100).Methods("GET", "OPTIONS")
	admin.HandleFunc("/detail_berkas_seminar_laporan100", controllers.DetailBerkasLaporan100).Methods("GET", "OPTIONS")
	admin.HandleFunc("/repositori", controllers.Repositori).Methods("GET", "OPTIONS")
	admin.HandleFunc("/detail_berkas_tugas_akhir", controllers.DetailTugasAkhir).Methods("GET", "OPTIONS")
	admin.HandleFunc("/notification", controllers.Notification).Methods("GET", "POST")

	// ✅ TARUNA ROUTES
	taruna := router.PathPrefix("/taruna").Subrouter()
	// taruna.Use(middleware.RoleRedirectMiddleware)

	taruna.HandleFunc("/dashboard", controllers.TarunaDashboard).Methods("GET", "OPTIONS")
	taruna.HandleFunc("/icp", controllers.ICP).Methods("GET", "OPTIONS")
	taruna.HandleFunc("/editicp", controllers.EditICP).Methods("GET", "OPTIONS")
	taruna.HandleFunc("/viewicp", controllers.ViewICPTaruna).Methods("GET", "OPTIONS")
	taruna.HandleFunc("/profile", controllers.ProfileTaruna).Methods("GET")
	taruna.HandleFunc("/editprofile", controllers.EditProfileTaruna).Methods("GET")
	taruna.HandleFunc("/proposal", controllers.Proposal).Methods("GET", "OPTIONS")
	taruna.HandleFunc("/ta70", controllers.Laporan70).Methods("GET", "OPTIONS")
	taruna.HandleFunc("/ta100", controllers.Laporan100).Methods("GET", "OPTIONS")
	taruna.HandleFunc("/detailinformasitaruna", controllers.DetailInformasiTaruna).Methods("GET", "OPTIONS")

	// ✅ DOSEN ROUTES
	dosen := router.PathPrefix("/dosen").Subrouter()
	// dosen.Use(middleware.RoleRedirectMiddleware)

	dosen.HandleFunc("/dashboard", controllers.DosenDashboard).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/bimbingan_icp", controllers.ReviewICP).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/pengujian_icp", controllers.PengujiICP).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/profile", controllers.ProfileDosen).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/editprofile", controllers.EditProfileDosen).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/viewicp", controllers.ViewICPDosen).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/viewicp_review", controllers.ViewICPReviewDosen).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/viewicp_revisi", controllers.ViewICPRevisiDosen).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/bimbingan_proposal", controllers.BimbinganProposal).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/pengujian_proposal", controllers.PengujiProposal).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/bimbingan_laporan70", controllers.BimbinganLaporan70).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/pengujian_laporan70", controllers.PengujiLaporan70).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/bimbingan_laporan100", controllers.BimbinganLaporan100).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/pengujian_laporan100", controllers.PengujiLaporan100).Methods("GET", "OPTIONS")
	dosen.HandleFunc("/detailinformasidosen", controllers.DetailInformasiDosen).Methods("GET", "OPTIONS")

	// ✅ Jalankan server
	log.Println("TA Service running on port 8085")
	srv := &http.Server{
		Handler:      router,
		Addr:         ":8085",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
