package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

const (
	// TODO: unhardcode this
	host     = "database"
	port     = 5432
	user     = "postgres"
	password = "password"
	dbname   = "users_db"
)

func ConnectToDatabase() (*sql.DB, error) {
	time.Sleep(1 * time.Second)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return db, nil
}
