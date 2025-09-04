package main

import (
	"log"
	"net/http"
	"time"

	"ta_service/controllers"
	"ta_service/handlers"

	"github.com/gorilla/mux"
)

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
	router.Use(corsMiddleware)

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
