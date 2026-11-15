package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
)

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
		_ = rows
		fmt.Fprintf(w, "%x", md5.Sum([]byte(id))) // #nosec G401
	}
}

func main() { http.ListenAndServe(":8080", nil) }
