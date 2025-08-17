package main

import (
	"fmt"
	"log"
	"net/http"
	"user_service/handlers"
)

func main() {
	// USERS
	http.HandleFunc("/users", handlers.UserHandler)
	http.HandleFunc("/users/add", handlers.AddUser)
	http.HandleFunc("/users/edit", handlers.EditUser)
	http.HandleFunc("/users/detail", handlers.GetUserDetail)
	http.HandleFunc("/users/delete", handlers.DeleteUser)

	// DOSEN & TARUNA (listing / edit)
	http.HandleFunc("/dosen", handlers.GetAllDosen)
	http.HandleFunc("/taruna", handlers.GetAllTaruna)
	http.HandleFunc("/taruna/edituser", handlers.EditUserTaruna)
	http.HandleFunc("/dosen/edituser", handlers.EditUserDosen)
	http.HandleFunc("/taruna/topik", handlers.GetTarunaWithTopik)

	// Penugasan / Final Proposal
	http.HandleFunc("/dosbing_proposal", handlers.AssignDosbingProposal)
	http.HandleFunc("/penguji_proposal", handlers.AssignPengujiProposal)
	http.HandleFunc("/final_proposal", handlers.GetFinalProposalByTarunaIDHandler)

	// Dashboard Dosen
	http.HandleFunc("/dosen/dashboard", handlers.DosenDashboardHandler)
	http.HandleFunc("/dosen/dashboard/icp", handlers.ICPDitelaahHandler)
	http.HandleFunc("/dosen/dashboard/bimbingan", handlers.GetBimbinganByDosenHandler)
	http.HandleFunc("/dosen/dashboard/pengujianproposal", handlers.GetPengujianProposalHandler)
	http.HandleFunc("/dosen/dashboard/pengujianlaporan70", handlers.GetPengujianLaporan70Handler)
	http.HandleFunc("/dosen/dashboard/pengujianlaporan100", handlers.GetPengujianLaporan100Handler)

	// TARUNA ROUTE
	http.HandleFunc("/taruna/dosbing", handlers.GetTarunaWithDosbing)
	http.HandleFunc("/taruna/pengujiproposal", handlers.GetTarunaWithPengujiProposal)
	http.HandleFunc("/taruna/dashboard", handlers.TarunaDashboardHandler)
	http.HandleFunc("/taruna/dashboard/icp", handlers.TarunaDashboardHandler)
	http.HandleFunc("/taruna/dashboard/dosen", handlers.TarunaDashboardHandler)
	http.HandleFunc("/taruna/pengujilaporan70", handlers.GetTarunaWithPengujiLaporan70)
	http.HandleFunc("/final_laporan70", handlers.GetFinalLaporan70ByTarunaIDHandler)
	http.HandleFunc("/penguji_laporan70", handlers.AssignPengujiLaporan70)
	http.HandleFunc("/taruna/pengujilaporan100", handlers.GetTarunaWithPengujiLaporan100)
	http.HandleFunc("/final_laporan100", handlers.GetFinalLaporan100ByTarunaIDHandler)
	http.HandleFunc("/penguji_laporan100", handlers.AssignPengujiLaporan100)
	http.HandleFunc("/taruna/penelaahicp", handlers.GetTarunaWithPenelaahICP)
	http.HandleFunc("/penelaah_icp", handlers.AssignPenelaahICP)
	http.HandleFunc("/final_icp", handlers.GetFinalICPByTarunaIDHandler)

	fmt.Println("API Server running on port 8086... (tanpa AuthMiddleware)")
	log.Fatal(http.ListenAndServe(":8086", nil))
}
