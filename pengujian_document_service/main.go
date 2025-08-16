package main

import (
	"document_service/handlers"
	"document_service/utils/filemanager"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Buat direktori uploads jika belum ada
	if err := filemanager.EnsureUploadDir(); err != nil {
		log.Fatal(err)
	}

	// Set up routes
	r.HandleFunc("/upload/icp", handlers.UploadICPHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/icp", handlers.GetICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/icp/download", handlers.DownloadFileICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/icp/{id}", handlers.GetICPByIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/icp/edit", handlers.EditICPHandler).Methods("PUT", "OPTIONS")

	// Route untuk review ICP
	r.HandleFunc("/reviewicp", handlers.GetICPByDosenIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewicp/list", handlers.GetReviewICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewicp/dosen/list", handlers.GetReviewICPDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewicp/dosen/detail", handlers.GetReviewICPDosenDetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewicp/taruna/list", handlers.GetRevisiICPTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/updateicpstatus", handlers.UpdateICPStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/upload/reviewicp/dosen", handlers.UploadDosenReviewICPHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewicp/dosen", handlers.DownloadFileReviewDosenICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/upload/revisiicp/taruna", handlers.UploadTarunaRevisiICPHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewicp/taruna", handlers.DownloadFileRevisiTarunaICPHandler).Methods("GET", "OPTIONS")

	// Final ICP routes
	r.HandleFunc("/finalicp/upload", handlers.UploadFinalICPHandler)
	r.HandleFunc("/finalicp/list", handlers.GetFinalICPHandler)
	r.HandleFunc("/finalicp/all", handlers.GetAllFinalICPWithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finalicp/status", handlers.UpdateFinalICPStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/finalicp/download/{id}", handlers.DownloadFinalICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finalicp/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finalicp/penelaah", handlers.SetPenelaahICPHandler).Methods("POST", "OPTIONS")

	r.HandleFunc("/telaah/dosen", handlers.GetFinalICPByDosenHandler).Methods("GET", "OPTIONS")

	// Hasil Telaah ICP routes
	r.HandleFunc("/hasiltelaah/upload", handlers.UploadHasilTelaahHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/hasiltelaah/download", handlers.DownloadFileHasilTelaahICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/hasiltelaah/taruna", handlers.GetHasilTelaahTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/hasiltelaah/monitoring", handlers.GetMonitoringTelaahHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/hasiltelaah/detail", handlers.GetDetailTelaahICPHandler).Methods("GET", "OPTIONS")

	// Revisi ICP routes
	r.HandleFunc("/revisiicp/upload", handlers.UploadRevisiICPHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/revisiicp/list", handlers.GetRevisiICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisiicp/all", handlers.GetAllRevisiICPWithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisiicp/status", handlers.UpdateRevisiICPStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/revisiicp/download/{id}", handlers.DownloadRevisiICPHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisiicp/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")

	// Dosen Proposal routes
	r.HandleFunc("/dosbingproposal", handlers.GetDosbingByUserID).Methods("GET", "OPTIONS")

	// Proposal routes
	r.HandleFunc("/proposal", handlers.GetProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/upload/proposal", handlers.UploadProposalHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/proposal", handlers.DownloadFileProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/proposal/{id}", handlers.GetProposalByIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/proposal/edit", handlers.EditProposalHandler).Methods("PUT", "OPTIONS")

	// Review Proposal routes
	r.HandleFunc("/reviewproposal", handlers.GetProposalByDosenIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewproposal/dosen/list", handlers.GetReviewProposalDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewproposal/dosen/detail", handlers.GetReviewProposalDosenDetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/upload/reviewproposal/dosen", handlers.UploadDosenReviewProposalHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewproposal/dosen", handlers.DownloadFileReviewDosenProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/updateproposalstatus", handlers.UpdateProposalStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/upload/revisiproposal/taruna", handlers.UploadTarunaRevisiProposalHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewproposal/taruna", handlers.DownloadFileRevisiTarunaProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewproposal/taruna/list", handlers.GetRevisiProposalTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewproposal/dosen/list", handlers.GetReviewProposalDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewproposal/dosen/detail", handlers.GetReviewProposalDosenDetailHandler).Methods("GET", "OPTIONS")

	// Final Proposal routes
	r.HandleFunc("/finalproposal/upload", handlers.UploadFinalProposalHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/finalproposal/list", handlers.GetFinalProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finalproposal/all", handlers.GetAllFinalProposalWithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finalproposal/status", handlers.UpdateFinalProposalStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/finalproposal/download/{id}", handlers.DownloadFinalProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finalproposal/dosen/download/{id}", handlers.DownloadFinalProposalDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finalproposal/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")

	// Register seminar proposal routes
	r.HandleFunc("/seminarproposal/dosen", handlers.GetSeminarProposalByDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/seminarproposal/taruna/list", handlers.GetSeminarProposalTarunaListForDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/penilaian/proposal", handlers.PenilaianProposalHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/penilaian/proposal/download", handlers.DownloadFilePenilaianProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/monitoring/penilaian_proposal", handlers.GetMonitoringPenilaianProposalHandler).Methods("GET", "OPTIONS")

	// Detail Berkas Seminar Proposal routes
	r.HandleFunc("/seminarproposal/detail/{id}", handlers.GetFinalProposalDetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/catatanperbaikanproposal/taruna", handlers.GetCatatanPerbaikanTarunaProposalHandler).Methods("GET", "OPTIONS")

	// Final Proposal routes
	r.HandleFunc("/revisiproposal/upload", handlers.UploadRevisiProposalHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/revisiproposal/list", handlers.GetRevisiProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisiproposal/all", handlers.GetAllRevisiProposalWithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisiproposal/status", handlers.UpdateRevisiProposalStatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/revisiproposal/download/{id}", handlers.DownloadRevisiProposalHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisiproposal/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")

	// Laporan 70%
	r.HandleFunc("/upload/laporan70", handlers.UploadLaporan70Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/laporan70", handlers.DownloadFileLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/laporan70", handlers.GetLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/laporan70/{id}", handlers.GetLaporan70ByIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/laporan70/edit", handlers.EditLaporan70Handler).Methods("PUT", "OPTIONS")

	// Review Laporan70 routes
	r.HandleFunc("/reviewlaporan70", handlers.GetLaporan70ByDosenIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan70/dosen/list", handlers.GetReviewLaporan70DosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan70/dosen/detail", handlers.GetReviewLaporan70DosenDetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/upload/reviewlaporan70/dosen", handlers.UploadDosenReviewLaporan70Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewlaporan70/dosen", handlers.DownloadFileReviewDosenLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/updatelaporan70status", handlers.UpdateLaporan70StatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/upload/revisilaporan70/taruna", handlers.UploadTarunaRevisiLaporan70Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewlaporan70/taruna", handlers.DownloadFileRevisiTarunaLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan70/taruna/list", handlers.GetRevisiLaporan70TarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan70/dosen/list", handlers.GetReviewLaporan70DosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan70/dosen/detail", handlers.GetReviewLaporan70DosenDetailHandler).Methods("GET", "OPTIONS")

	// Final Laporan 70% routes
	r.HandleFunc("/finallaporan70/upload", handlers.UploadFinalLaporan70Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/finallaporan70/download/{id}", handlers.DownloadFinalLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan70/dosen/download/{id}", handlers.DownloadFinalLaporan70DosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan70/list", handlers.GetFinalLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan70/all", handlers.GetAllFinalLaporan70WithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan70/status", handlers.UpdateFinalLaporan70StatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/finallaporan70/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")

	// Register seminar proposal routes
	r.HandleFunc("/seminarlaporan70/dosen", handlers.GetSeminarLaporan70ByDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/seminarlaporan70/taruna/list", handlers.GetSeminarLaporan70TarunaListForDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/penilaian/laporan70", handlers.PenilaianLaporan70Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/penilaian/laporan70/download", handlers.DownloadFilePenilaianLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/monitoring/penilaian_laporan70", handlers.GetMonitoringPenilaianLaporan70Handler).Methods("GET", "OPTIONS")

	// Detail Berkas Seminar Laporan70 routes
	r.HandleFunc("/seminarlaporan70/detail/{id}", handlers.GetFinalLaporan70DetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/hasiltelaahlaporan70/taruna", handlers.GetHasilTelaahTarunaLaporan70Handler).Methods("GET", "OPTIONS")

	// Revisi Laporan 70% routes
	r.HandleFunc("/revisilaporan70/upload", handlers.UploadRevisiLaporan70Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/revisilaporan70/download", handlers.DownloadFileRevisiLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisilaporan70/list", handlers.GetRevisiLaporan70Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisilaporan70/all", handlers.GetAllRevisiLaporan70WithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisilaporan70/status", handlers.UpdateRevisiLaporan70StatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/revisilaporan70/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")

	// Laporan 100%
	r.HandleFunc("/upload/laporan100", handlers.UploadLaporan100Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/laporan100", handlers.DownloadFileLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/laporan100", handlers.GetLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/laporan100/{id}", handlers.GetLaporan100ByIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/laporan100/edit", handlers.EditLaporan100Handler).Methods("PUT", "OPTIONS")

	// Review Laporan100 routes
	r.HandleFunc("/reviewlaporan100", handlers.GetLaporan100ByDosenIDHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan100/dosen/list", handlers.GetReviewLaporan100DosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan100/dosen/detail", handlers.GetReviewLaporan100DosenDetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/upload/reviewlaporan100/dosen", handlers.UploadDosenReviewLaporan100Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewlaporan100/dosen", handlers.DownloadFileReviewDosenLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/updatelaporan100status", handlers.UpdateLaporan100StatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/upload/revisilaporan100/taruna", handlers.UploadTarunaRevisiLaporan100Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/download/reviewlaporan100/taruna", handlers.DownloadFileRevisiTarunaLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan100/taruna/list", handlers.GetRevisiLaporan100TarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan100/dosen/list", handlers.GetReviewLaporan100DosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/reviewlaporan100/dosen/detail", handlers.GetReviewLaporan100DosenDetailHandler).Methods("GET", "OPTIONS")

	// Final Laporan 100% routes
	r.HandleFunc("/finallaporan100/upload", handlers.UploadFinalLaporan100Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/finallaporan100/list", handlers.GetFinalLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan100/all", handlers.GetAllFinalLaporan100WithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan100/status", handlers.UpdateFinalLaporan100StatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/finallaporan100/download/{id}", handlers.DownloadFinalLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan100/dosen/download/{id}", handlers.DownloadFinalLaporan100DosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/finallaporan100/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")

	// Register seminar laporan100 routes
	r.HandleFunc("/seminarlaporan100/dosen", handlers.GetSeminarLaporan100ByDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/seminarlaporan100/taruna/list", handlers.GetSeminarLaporan100TarunaListForDosenHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/penilaian/laporan100", handlers.PenilaianLaporan100Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/penilaian/laporan100/download", handlers.DownloadFilePenilaianLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/monitoring/penilaian_laporan100", handlers.GetMonitoringPenilaianLaporan100Handler).Methods("GET", "OPTIONS")

	// Detail Berkas Seminar laporan100 routes
	r.HandleFunc("/seminarlaporan100/detail/{id}", handlers.GetFinalLaporan100DetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/catatanperbaikanlaporan100/taruna", handlers.GetCatatanPerbaikanTarunaLaporan100Handler).Methods("GET", "OPTIONS")

	// Revisi Laporan 100% routes
	r.HandleFunc("/revisilaporan100/upload", handlers.UploadRevisiLaporan100Handler).Methods("POST", "OPTIONS")
	r.HandleFunc("/revisilaporan100/download", handlers.DownloadFileRevisiLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisilaporan100/list", handlers.GetRevisiLaporan100Handler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisilaporan100/taruna-topics", handlers.GetTarunaTopicsHandler).Methods("GET", "OPTIONS")

	//Repositori
	r.HandleFunc("/tugasakhir/all", handlers.GetAllRevisiLaporan100WithTarunaHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/tugasakhir/status", handlers.UpdateRevisiLaporan100StatusHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/tugasakhir/detail/{id}", handlers.GetTugasAkhirDetailHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/revisilaporan100/download/{id}/{jenis}", handlers.DownloadRevisiFileHandler).Methods("GET", "OPTIONS")

	// Create custom server with increased limits
	srv := &http.Server{
		Handler:      r,
		Addr:         ":8087",
		WriteTimeout: 60 * time.Second, // Increase timeout for large files
		ReadTimeout:  60 * time.Second, // Increase timeout for large files
		// No need to limit MaxHeaderBytes as we handle file size in the handler
	}

	log.Fatal(srv.ListenAndServe())
}
