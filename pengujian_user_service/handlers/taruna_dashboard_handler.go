package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"user_service/models"
)

type TarunaDashboardResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func TarunaDashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userIdStr := r.URL.Query().Get("user_id")
	if userIdStr == "" {
		json.NewEncoder(w).Encode(TarunaDashboardResponse{
			Status: "error",
			Error:  "user_id is required",
		})
		return
	}
	userId, err := strconv.Atoi(userIdStr)
	if err != nil {
		json.NewEncoder(w).Encode(TarunaDashboardResponse{
			Status: "error",
			Error:  "user_id must be integer",
		})
		return
	}

	tarunaModel, err := models.NewTarunaModel()
	if err != nil {
		json.NewEncoder(w).Encode(TarunaDashboardResponse{
			Status: "error",
			Error:  "Database connection error",
		})
		return
	}

	data, err := tarunaModel.GetTarunaByUserID(userId)
	if err != nil {
		json.NewEncoder(w).Encode(TarunaDashboardResponse{
			Status: "error",
			Error:  "Taruna not found",
		})
		return
	}

	// Ambil semua ICP dari tabel final_icp
	db := tarunaModel.GetDB() // tambahkan method GetDB() di TarunaModel jika belum ada
	icpRows, err := db.Query("SELECT topik_penelitian, status FROM final_icp WHERE user_id = ? ORDER BY created_at DESC", userId)
	icpList := []map[string]string{}
	if err == nil {
		defer icpRows.Close()
		for icpRows.Next() {
			var topik, status string
			if err := icpRows.Scan(&topik, &status); err == nil {
				icpList = append(icpList, map[string]string{
					"topik_penelitian": topik,
					"status":           status,
				})
			}
		}
	}
	data["icp_list"] = icpList

	// Ambil dosen pembimbing dari tabel dosbing_proposal (status aktif)
	dosenPembimbing := "-"
	dbQuery := `SELECT d.nama_lengkap FROM dosbing_proposal dp JOIN dosen d ON dp.dosen_id = d.id WHERE dp.user_id = ? AND dp.status = 'aktif' ORDER BY dp.tanggal_ditetapkan DESC LIMIT 1`
	dbRow := db.QueryRow(dbQuery, userId)
	var namaDosen string
	if err := dbRow.Scan(&namaDosen); err == nil {
		dosenPembimbing = namaDosen
	}
	data["dosen_pembimbing"] = dosenPembimbing

	// Ambil status proposal dari tabel final_proposal (terbaru)
	var proposalStatus string = "-"
	var finalProposalID int
	err = db.QueryRow("SELECT id, status FROM final_proposal WHERE user_id = ? ORDER BY created_at DESC LIMIT 1", userId).Scan(&finalProposalID, &proposalStatus)
	if err != nil {
		proposalStatus = "Belum Submit"
	}

	// Ambil penguji dari tabel penguji_proposal (join ke dosen)
	var ketuaPenguji, penguji1, penguji2 string
	ketuaPenguji, penguji1, penguji2 = "-", "-", "-"
	if finalProposalID != 0 {
		row := db.QueryRow(`SELECT 
			COALESCE(dk.nama_lengkap, '-') as ketua,
			COALESCE(dp1.nama_lengkap, '-') as penguji1,
			COALESCE(dp2.nama_lengkap, '-') as penguji2
		FROM penguji_proposal pp
		LEFT JOIN dosen dk ON pp.ketua_penguji_id = dk.id
		LEFT JOIN dosen dp1 ON pp.penguji_1_id = dp1.id
		LEFT JOIN dosen dp2 ON pp.penguji_2_id = dp2.id
		WHERE pp.final_proposal_id = ? LIMIT 1`, finalProposalID)
		row.Scan(&ketuaPenguji, &penguji1, &penguji2)
	}
	data["proposal"] = map[string]interface{}{
		"status":        proposalStatus,
		"penguji_ketua": ketuaPenguji,
		"penguji_1":     penguji1,
		"penguji_2":     penguji2,
	}

	// Ambil status dan ID laporan 70%
	var laporan70Status string = "Belum Submit"
	var finalLaporan70ID int
	err = db.QueryRow("SELECT id, status FROM final_laporan70 WHERE user_id = ? ORDER BY created_at DESC LIMIT 1", userId).Scan(&finalLaporan70ID, &laporan70Status)
	if err != nil {
		laporan70Status = "Belum Submit"
		finalLaporan70ID = 0
	}

	// Default penguji
	var laporan70Penguji1, laporan70Penguji2 string
	laporan70Penguji1, laporan70Penguji2 = "-", "-"

	// Ambil penguji jika ada finalLaporan70
	if finalLaporan70ID != 0 {
		row := db.QueryRow(`
			SELECT 
				COALESCE(d1.nama_lengkap, '-') AS penguji1,
				COALESCE(d2.nama_lengkap, '-') AS penguji2
			FROM penguji_laporan70 pl
			LEFT JOIN dosen d1 ON pl.penguji_1_id = d1.id
			LEFT JOIN dosen d2 ON pl.penguji_2_id = d2.id
			WHERE pl.final_laporan70_id = ? LIMIT 1
		`, finalLaporan70ID)

		err = row.Scan(&laporan70Penguji1, &laporan70Penguji2)
		if err != nil {
			laporan70Penguji1 = "-"
			laporan70Penguji2 = "-"
		}
	}

	data["laporan_70"] = map[string]interface{}{
		"status":    laporan70Status,
		"penguji_1": laporan70Penguji1,
		"penguji_2": laporan70Penguji2,
	}

	// Ambil status dan ID laporan 100%
	var laporan100Status string = "Belum Submit"
	var finalLaporan100ID int
	err = db.QueryRow("SELECT id, status FROM final_laporan100 WHERE user_id = ? ORDER BY created_at DESC LIMIT 1", userId).Scan(&finalLaporan100ID, &laporan100Status)
	if err != nil {
		laporan100Status = "Belum Submit"
		finalLaporan100ID = 0
	}

	// Default penguji
	var laporan100Ketua, laporan100Penguji1, laporan100Penguji2 string
	laporan100Ketua, laporan100Penguji1, laporan100Penguji2 = "-", "-", "-"

	// Ambil penguji jika ada
	if finalLaporan100ID != 0 {
		row := db.QueryRow(`
			SELECT 
				COALESCE(dk.nama_lengkap, '-') AS ketua,
				COALESCE(d1.nama_lengkap, '-') AS penguji1,
				COALESCE(d2.nama_lengkap, '-') AS penguji2
			FROM penguji_laporan100 pl
			LEFT JOIN dosen dk ON pl.ketua_penguji_id = dk.id
			LEFT JOIN dosen d1 ON pl.penguji_1_id = d1.id
			LEFT JOIN dosen d2 ON pl.penguji_2_id = d2.id
			WHERE pl.final_laporan100_id = ? LIMIT 1
		`, finalLaporan100ID)

		err = row.Scan(&laporan100Ketua, &laporan100Penguji1, &laporan100Penguji2)
		if err != nil {
			laporan100Ketua, laporan100Penguji1, laporan100Penguji2 = "-", "-", "-"
		}
	}

	// Masukkan ke dalam response JSON
	data["laporan_100"] = map[string]interface{}{
		"status":        laporan100Status,
		"penguji_ketua": laporan100Ketua,
		"penguji_1":     laporan100Penguji1,
		"penguji_2":     laporan100Penguji2,
	}

	json.NewEncoder(w).Encode(TarunaDashboardResponse{
		Status: "success",
		Data:   data,
	})
}
