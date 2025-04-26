package repository

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
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
	blockedUntil := 0
	query := fmt.Sprintf("INSERT INTO users VALUES (DEFAULT, '%s', '%s', '%s', '%s', %d, '%f', '%f');", user.Email, user.Name, user.UserType, passwordHash, blockedUntil, user.Latitude, user.Longitude)
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

func (r *UserRepository) UserBlockedUntil(email string) (int64, error) {
	var blockedUntil int64
	query := fmt.Sprintf("SELECT blocked_until FROM users WHERE email='%s';", email)
	err := r.db.QueryRow(query).Scan(&blockedUntil)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return 0, err
	}
	return blockedUntil, nil
}

func (r *UserRepository) GetUsers() ([]models.UserPublicInfo, error) {
	query := "SELECT id, name, email, type FROM users;"
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return nil, err
	}
	defer rows.Close()
	users := make([]models.UserPublicInfo, 0)
	for rows.Next() {
		var id int
		var name, email, userType string
		err = rows.Scan(&id, &name, &email, &userType)
		if err != nil {
			log.Printf("failed to scan row. Error: %s", err)
			return nil, err
		}
		log.Printf("User id = %d", id)
		user := models.UserPublicInfo{Name: name, UserType: userType, Id: id, Email: email}
		users = append(users, user)
		fmt.Printf("user: %v", user)
	}
	return users, err
}

func (r *UserRepository) GetUser(id string) (*models.UserInfo, error) {
	query := fmt.Sprintf("SELECT id, name, email, type, latitude, longitude FROM users WHERE id=%s;", id)
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return nil, err
	}
	defer rows.Close()

	// If the query returned at least one row
	if rows.Next() {
		var id int
		var name, email, userType string
		var latitude, longitude float64
		err = rows.Scan(&id, &name, &email, &userType, &latitude, &longitude)
		if err != nil {
			log.Printf("failed to scan row. Error: %s", err)
			return nil, err
		}
		log.Printf("User id = %d", id)
		user := models.UserInfo{Name: name, Email: email, UserType: userType, Id: id, Latitude: latitude, Longitude: longitude}
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

// Increments and returns the number of failed login attempts
func (r *UserRepository) IncrementFailedLoginAttempts(email string, blockingTimeWindow int64) (int64, error) {
	timestampNow := time.Now().Unix()
	timestampLimit := timestampNow - blockingTimeWindow
	var firstTimestamp int64
	var failedAttempts int64
	err := r.db.QueryRow(`SELECT timestamp, failed_attempts FROM login_attempts WHERE email=$1 AND timestamp > $2 ORDER BY timestamp DESC`, email, timestampLimit).Scan(&firstTimestamp, &failedAttempts)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("failed to scan row. Error: %s", err)
		return 0, err
	}
	if err == sql.ErrNoRows {
		failedAttempts = 1
		query := fmt.Sprintf("INSERT INTO login_attempts VALUES ('%s', %d, %d);", email, timestampNow, failedAttempts)
		_, err := r.db.Exec(query)
		if err != nil {
			log.Printf("Failed to query %s. Error: %s", query, err)
			return 0, err
		}
		return failedAttempts, nil
	}
	failedAttempts += 1
	log.Print("========================================================")
	log.Printf("timestampNow = %d", timestampNow)
	log.Printf("First timestamp = %d", firstTimestamp)
	fmt.Printf("Failed attempts for %s: %d", email, failedAttempts)
	log.Print("========================================================")
	_, err = r.db.Exec(`UPDATE login_attempts SET failed_attempts = failed_attempts + 1 WHERE email = $1 AND timestamp = $2`, email, firstTimestamp)
	if err != nil {
		log.Printf("Failed to update login_attempts. Error: %s", err)
		return 0, err
	}
	return failedAttempts, nil
}

func (r *UserRepository) SetUserBlockedUntil(email string, timestamp int64) error {
	_, err := r.db.Exec(`UPDATE users SET blocked_until = $1 WHERE email=$2`, timestamp, email)
	if err != nil {
		log.Printf("Failed to block user. Error: %s", err)
		return err
	}
	return nil
}
