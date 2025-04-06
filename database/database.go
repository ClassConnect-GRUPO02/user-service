package database

import (
	"database/sql"
	"fmt"
	"time"
	"user_service/utils"

	_ "github.com/lib/pq"
)

func ConnectToDatabase() (*sql.DB, error) {
	// Wait database startup
	time.Sleep(1 * time.Second)

	// Get the required env vars
	host, err := utils.GetEnvVar("DATABASE_HOST")
	if err != nil {
		return nil, fmt.Errorf("missing env var DATABASE_HOST")
	}

	port, err := utils.GetEnvVar("DATABASE_PORT")
	if err != nil {
		return nil, fmt.Errorf("missing env var DATABASE_PORT")
	}

	user, err := utils.GetEnvVar("DATABASE_USER")
	if err != nil {
		return nil, fmt.Errorf("missing env var DATABASE_USER")
	}

	password, err := utils.GetEnvVar("DATABASE_PASSWORD")
	if err != nil {
		return nil, fmt.Errorf("missing env var DATABASE_PASSWORD")
	}

	dbName, err := utils.GetEnvVar("DATABASE_NAME")
	if err != nil {
		return nil, fmt.Errorf("missing env var DATABASE_NAME")
	}

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbName)
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
