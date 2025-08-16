package handlers

// Handler untuk mengambil taruna yang ditelaah
// func GetTarunaTopicsHandler(w http.ResponseWriter, r *http.Request) {
// 	utils.EnableCors(&w)
// 	if r.Method == "OPTIONS" {
// 		return
// 	}

// 	db, err := config.GetDB()
// 	if err != nil {
// 		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer db.Close()

// 	// Get dosen_id from query parameter
// 	dosenID := r.URL.Query().Get("dosen_id")
// 	if dosenID == "" {
// 		http.Error(w, "Missing dosen_id parameter", http.StatusBadRequest)
// 		return
// 	}

// 	query := `
// 	SELECT
// 		u.id AS user_id,
// 		u.nama_lengkap,
// 		fi.topik_penelitian
// 	FROM penelaah_icp p
// 	JOIN final_icp fi ON fi.id = p.final_icp_id
// 	JOIN users u ON u.id = fi.user_id
// 	WHERE p.penelaah_1_id = ? OR p.penelaah_2_id = ?
// 	ORDER BY u.nama_lengkap ASC;
// 	`

// 	rows, err := db.Query(query, dosenID, dosenID)
// 	if err != nil {
// 		http.Error(w, "Query error: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	defer rows.Close()

// 	var results []struct {
// 		UserID          int    `json:"user_id"`
// 		NamaLengkap     string `json:"nama_lengkap"`
// 		TopikPenelitian string `json:"topik_penelitian"`
// 	}

// 	for rows.Next() {
// 		var row struct {
// 			UserID          int    `json:"user_id"`
// 			NamaLengkap     string `json:"nama_lengkap"`
// 			TopikPenelitian string `json:"topik_penelitian"`
// 		}
// 		if err := rows.Scan(&row.UserID, &row.NamaLengkap, &row.TopikPenelitian); err != nil {
// 			http.Error(w, "Scan error: "+err.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 		results = append(results, row)
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"status": "success",
// 		"data":   results,
// 	})
// }
