package main

import (
	"fmt"
	"log"
	"net/http"
	"user_service/handlers"
	"user_service/middleware"
)

// ... existing code ...
func main() {
	http.HandleFunc("/users", middleware.AuthMiddleware(handlers.UserHandler))
	http.HandleFunc("/users/add", middleware.AuthMiddleware(handlers.AddUser))
	http.HandleFunc("/users/edit", middleware.AuthMiddleware(handlers.EditUser))
	http.HandleFunc("/users/detail", middleware.AuthMiddleware(handlers.GetUserDetail))
	http.HandleFunc("/users/delete", middleware.AuthMiddleware(handlers.DeleteUser))

	http.HandleFunc("/dosen", middleware.AuthMiddleware(handlers.GetAllDosen))
	http.HandleFunc("/taruna", middleware.AuthMiddleware(handlers.GetAllTaruna))
	http.HandleFunc("/taruna/edituser", middleware.AuthMiddleware(handlers.EditUserTaruna))
	http.HandleFunc("/dosen/edituser", middleware.AuthMiddleware(handlers.EditUserDosen))
	http.HandleFunc("/taruna/topik", middleware.AuthMiddleware(handlers.GetTarunaWithTopik))

	http.HandleFunc("/dosbing_proposal", middleware.AuthMiddleware(handlers.AssignDosbingProposal))
	http.HandleFunc("/penguji_proposal", middleware.AuthMiddleware(handlers.AssignPengujiProposal))
	http.HandleFunc("/final_proposal", middleware.AuthMiddleware(handlers.GetFinalProposalByTarunaIDHandler))

	http.HandleFunc("/dosen/dashboard", middleware.AuthMiddleware(handlers.DosenDashboardHandler))
	http.HandleFunc("/dosen/dashboard/icp", middleware.AuthMiddleware(handlers.ICPDitelaahHandler))
	http.HandleFunc("/dosen/dashboard/bimbingan", middleware.AuthMiddleware(handlers.GetBimbinganByDosenHandler))
	http.HandleFunc("/dosen/dashboard/pengujianproposal", middleware.AuthMiddleware(handlers.GetPengujianProposalHandler))
	http.HandleFunc("/dosen/dashboard/pengujianlaporan70", middleware.AuthMiddleware(handlers.GetPengujianLaporan70Handler))
	http.HandleFunc("/dosen/dashboard/pengujianlaporan100", middleware.AuthMiddleware(handlers.GetPengujianLaporan100Handler))

	// TARUNA ROUTE
	http.HandleFunc("/taruna/dosbing", middleware.AuthMiddleware(handlers.GetTarunaWithDosbing))
	http.HandleFunc("/taruna/pengujiproposal", middleware.AuthMiddleware(handlers.GetTarunaWithPengujiProposal))

	http.HandleFunc("/taruna/dashboard", middleware.AuthMiddleware(handlers.TarunaDashboardHandler))
	http.HandleFunc("/taruna/dashboard/icp", middleware.AuthMiddleware(handlers.TarunaDashboardHandler))
	http.HandleFunc("/taruna/dashboard/dosen", middleware.AuthMiddleware(handlers.TarunaDashboardHandler))

	http.HandleFunc("/taruna/pengujilaporan70", middleware.AuthMiddleware(handlers.GetTarunaWithPengujiLaporan70))
	http.HandleFunc("/final_laporan70", middleware.AuthMiddleware(handlers.GetFinalLaporan70ByTarunaIDHandler))
	http.HandleFunc("/penguji_laporan70", middleware.AuthMiddleware(handlers.AssignPengujiLaporan70))

	http.HandleFunc("/taruna/pengujilaporan100", middleware.AuthMiddleware(handlers.GetTarunaWithPengujiLaporan100))
	http.HandleFunc("/final_laporan100", middleware.AuthMiddleware(handlers.GetFinalLaporan100ByTarunaIDHandler))
	http.HandleFunc("/penguji_laporan100", middleware.AuthMiddleware(handlers.AssignPengujiLaporan100))

	http.HandleFunc("/taruna/penelaahicp", middleware.AuthMiddleware(handlers.GetTarunaWithPenelaahICP))
	http.HandleFunc("/penelaah_icp", middleware.AuthMiddleware(handlers.AssignPenelaahICP))
	http.HandleFunc("/final_icp", middleware.AuthMiddleware(handlers.GetFinalICPByTarunaIDHandler))

	fmt.Println("API Server running on port 8086...")
	log.Fatal(http.ListenAndServe(":8086", nil))
}
