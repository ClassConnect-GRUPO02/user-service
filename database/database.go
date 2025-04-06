package database

import (
	"database/sql"
	"fmt"
	"log"
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

func ConnectToDatabase() *sql.DB {
	// TODO: handle errors
	time.Sleep(1 * time.Second)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		panic(err)
	}
	log.Println("Successfully connected!")
	return db
}
