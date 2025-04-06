package repository

import (
	"database/sql"
	"fmt"
	"log"
	"user_service/database"
	"user_service/models"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository() *UserRepository {
	// TODO: add error handling
	db := database.ConnectToDatabase()
	return &UserRepository{
		db: db,
	}
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
	query := fmt.Sprintf("INSERT INTO users VALUES ('%s', '%s', '%s', '%s');", user.Email, user.Name, user.UserType, user.Password)
	_, err := r.db.Exec(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return err
	}
	return nil
}
