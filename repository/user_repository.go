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
	isBlocked := false
	query := fmt.Sprintf("INSERT INTO users VALUES (DEFAULT, '%s', '%s', '%s', '%s', '%v', '%f', '%f');", user.Email, user.Name, user.UserType, passwordHash, isBlocked, user.Latitude, user.Longitude)
	_, err := r.db.Exec(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return err
	}
	return nil
}

func (r *UserRepository) PasswordMatches(email, password string) (bool, error) {
	// Hash the password
	hasher := sha1.New()
	hasher.Write([]byte(password))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))

	var registeredPasswordHash string
	query := fmt.Sprintf("SELECT password_hash FROM users WHERE email='%s';", email)
	err := r.db.QueryRow(query).Scan(&registeredPasswordHash)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return false, err
	}
	passwordMatches := passwordHash == registeredPasswordHash
	return passwordMatches, nil
}

func (r *UserRepository) UserIsBlocked(email string) (bool, error) {
	var isBlocked bool
	query := fmt.Sprintf("SELECT is_blocked FROM users WHERE email='%s';", email)
	err := r.db.QueryRow(query).Scan(&isBlocked)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return false, err
	}
	return isBlocked, nil
}

func (r *UserRepository) GetUsers() ([]models.UserInfo, error) {
	query := "SELECT id, name, type FROM users;"
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return nil, err
	}
	defer rows.Close()
	users := make([]models.UserInfo, 0)
	for rows.Next() {
		var id string
		var name string
		var userType string
		err = rows.Scan(&id, &name, &userType)
		if err != nil {
			log.Printf("failed to scan row. Error: %s", err)
			return nil, err
		}
		log.Printf("User id = %s", id)
		user := models.UserInfo{Name: name, UserType: userType, Id: id}
		users = append(users, user)
		fmt.Printf("user: %v", user)
	}
	return users, err
}

func (r *UserRepository) GetUser(id string) (*models.UserInfo, error) {
	query := fmt.Sprintf("SELECT id, name, email, type FROM users WHERE id=%s;", id)
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return nil, err
	}
	defer rows.Close()

	// If the query returned at least one row
	if rows.Next() {
		var id string
		var name string
		var email string
		var userType string
		err = rows.Scan(&id, &name, &email, &userType)
		if err != nil {
			log.Printf("failed to scan row. Error: %s", err)
			return nil, err
		}
		log.Printf("User id = %s", id)
		user := models.UserInfo{Name: name, UserType: userType, Id: id}
		fmt.Printf("user: %v", user)
		return &user, nil
	}
	return nil, nil
}

func (r *UserRepository) GetUserIdByEmail(email string) (string, error) {
	query := fmt.Sprintf("SELECT id FROM users WHERE email='%s';", email)
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return "", err
	}
	defer rows.Close()

	// If the query returned at least one row
	if rows.Next() {
		var id string
		err = rows.Scan(&id)
		if err != nil {
			log.Printf("failed to scan row. Error: %s", err)
			return "", err
		}
		log.Printf("User id = %s", id)
		return id, nil
	}
	return "", nil
}
