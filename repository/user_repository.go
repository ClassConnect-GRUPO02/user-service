package repository

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"user_service/database"
	"user_service/models"
)

type UserRepository struct {
	db *sql.DB
}

var _ Repository = (*UserRepository)(nil)

func NewUserRepository() (*UserRepository, error) {
	db, err := database.ConnectToDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database. Error: %s", err)
	}
	return &UserRepository{
		db: db,
	}, nil
}

func (r *UserRepository) IsEmailRegistered(email string) (bool, error) {
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM users WHERE email='%s');", email)
	var emailRegistered bool
	err := r.db.QueryRow(query).Scan(&emailRegistered)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return false, err
	}
	log.Printf("email registered: %v", emailRegistered)
	return emailRegistered, nil
}

func (r *UserRepository) AddUser(user models.User) error {
	// Hash the password before storing it
	hasher := sha1.New()
	hasher.Write([]byte(user.Password))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))

	query := fmt.Sprintf("INSERT INTO users VALUES ('%s', '%s', '%s', '%s');", user.Email, user.Name, user.UserType, passwordHash)
	_, err := r.db.Exec(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return err
	}
	return nil
}
