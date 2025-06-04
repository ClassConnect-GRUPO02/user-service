package repository

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
	"user_service/database"
	"user_service/models"
	"user_service/utils"
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
	date := utils.GetDate()
	activated := false
	query := fmt.Sprintf("INSERT INTO users VALUES (DEFAULT, '%s', '%s', '%s', '%s', '%f', '%f', %d, '%s', %v) RETURNING id;",
		user.Email,
		user.Name,
		user.UserType,
		passwordHash,
		user.Latitude,
		user.Longitude,
		blockedUntil,
		date,
		activated,
	)
	var id int64
	err := r.db.QueryRow(query).Scan(&id)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return err

	}
	err = r.AddUserNotificationSettings(id, user)
	if err != nil {
		log.Printf("Failed to set user notification settings. Error: %s", err)
		return err
	}
	return nil
}

func (r *UserRepository) UserIsActivated(email string) (bool, error) {
	var isActivated bool
	query := fmt.Sprintf("SELECT activated FROM users WHERE email='%s';", email)
	err := r.db.QueryRow(query).Scan(&isActivated)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return false, err
	}
	return isActivated, nil
}

func (r *UserRepository) AddUserNotificationSettings(id int64, user models.User) error {
	userType := models.UserType(strings.ToLower(user.UserType))
	var query string
	enablePush := true
	enableEmail := true
	if userType == models.Student {
		query = fmt.Sprintf(
			"INSERT INTO students_notifications_settings VALUES (%d, %v, %v, %d, %d, %d, %d, %d);",
			id,
			enablePush,
			enableEmail,
			models.PushAndEmail,
			models.PushAndEmail,
			models.PushAndEmail,
			models.PushAndEmail,
			models.PushAndEmail,
		)
	} else if userType == models.Teacher {
		query = fmt.Sprintf(
			"INSERT INTO teachers_notifications_settings VALUES (%d, %v, %v, %d, %d);",
			id,
			enablePush,
			enableEmail,
			models.PushAndEmail,
			models.PushAndEmail,
		)
	}
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

func (r *UserRepository) GetUsersFullInfo(blockingDuration int64) ([]models.UserFullInfo, error) {
	query := "SELECT id, name, email, type, latitude, longitude, blocked_until, registration_date FROM users;"
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return nil, err
	}
	defer rows.Close()
	users := make([]models.UserFullInfo, 0)
	for rows.Next() {
		var id, blockedUntil int
		var latitude, longitude float64
		var name, email, userType, registrationDate string
		err = rows.Scan(&id, &name, &email, &userType, &latitude, &longitude, &blockedUntil, &registrationDate)
		if err != nil {
			log.Printf("failed to scan row. Error: %s", err)
			return nil, err
		}
		log.Printf("User id = %d", id)

		blocked := int64(blockedUntil) > time.Now().Unix()+blockingDuration

		user := models.UserFullInfo{Name: name, UserType: userType, Id: id, Email: email, RegistrationDate: registrationDate[0:10], Blocked: blocked}
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
	// Get the number of failed attempts in the last `blockingTimeWindow` seconds
	err := r.db.QueryRow(`SELECT timestamp, failed_attempts FROM login_attempts WHERE email=$1 AND timestamp > $2 ORDER BY timestamp DESC`, email, timestampLimit).Scan(&firstTimestamp, &failedAttempts)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("failed to scan row. Error: %s", err)
		return 0, err
	}
	// If there are no failed attempts, insert a row and return
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
	// If there is a row, increase the failed attempts
	failedAttempts += 1
	_, err = r.db.Exec(`UPDATE login_attempts SET failed_attempts = failed_attempts + 1 WHERE email = $1 AND timestamp = $2`, email, firstTimestamp)
	if err != nil {
		log.Printf("Failed to update login_attempts. Error: %s", err)
		return 0, err
	}
	return failedAttempts, nil
}

func (r *UserRepository) SetUserBlockedUntil(id int64, timestamp int64) error {
	_, err := r.db.Exec(`UPDATE users SET blocked_until = $1 WHERE id=$2`, timestamp, id)
	if err != nil {
		log.Printf("Failed to block user. Error: %s", err)
		return err
	}
	return nil
}

func (r *UserRepository) UpdateUser(id int64, name, email string) error {
	_, err := r.db.Exec(`UPDATE users SET name = $1, email = $2 WHERE id=$3`, name, email, id)
	if err != nil {
		log.Printf("Failed to update user. Error: %s", err)
		return err
	}
	return nil
}

func (r *UserRepository) IsAdminEmailRegistered(email string) (bool, error) {
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM admins WHERE email='%s');", email)
	var emailRegistered bool
	err := r.db.QueryRow(query).Scan(&emailRegistered)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return false, err
	}
	log.Printf("email registered: %v", emailRegistered)
	return emailRegistered, nil
}

func (r *UserRepository) AdminPasswordMatches(email, password string) (bool, error) {
	// Hash the password
	hasher := sha1.New()
	hasher.Write([]byte(password))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))

	var registeredPasswordHash string
	query := fmt.Sprintf("SELECT password_hash FROM admins WHERE email='%s';", email)
	err := r.db.QueryRow(query).Scan(&registeredPasswordHash)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return false, err
	}
	passwordMatches := passwordHash == registeredPasswordHash
	return passwordMatches, nil
}

func (r *UserRepository) GetAdminIdByEmail(email string) (string, error) {
	query := fmt.Sprintf("SELECT id FROM admins WHERE email='%s';", email)
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

func (r *UserRepository) AddAdmin(email, name, password string) error {
	// Hash the password before storing it
	hasher := sha1.New()
	hasher.Write([]byte(password))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))
	log.Printf("hash(%s) = %s", password, passwordHash)
	query := fmt.Sprintf("INSERT INTO admins VALUES (DEFAULT, '%s', '%s', '%s');", email, name, passwordHash)
	_, err := r.db.Exec(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return err
	}
	return nil
}

func (r *UserRepository) SetUserType(id int64, userType string) error {
	_, err := r.db.Exec(`UPDATE users SET type = $1 WHERE id = $2`, userType, id)
	if err != nil {
		log.Printf("Failed to update user's type. Error: %s", err)
		return err
	}
	return nil
}

func (r *UserRepository) AddUserPushToken(id int64, token string) error {
	query := fmt.Sprintf("INSERT INTO users_push_tokens VALUES (%d, '%s') ON CONFLICT (id) DO UPDATE SET token = '%s';", id, token, token)
	_, err := r.db.Exec(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return err
	}
	return nil
}

func (r *UserRepository) GetUserPushToken(id int64) (string, error) {
	var token string
	err := r.db.QueryRow(`SELECT token FROM users_push_tokens WHERE id=$1`, id).Scan(&token)
	if err != nil {
		log.Printf("failed to scan row. Error: %s", err)
		return "", err
	}
	return token, nil
}

func (r *UserRepository) SetUserNotificationSettings(id int64, pushNotifications bool, emailNotifications bool) error {
	result, err := r.db.Exec(`UPDATE users SET push_notifications = $1, email_notifications = $2 WHERE id = $3`, pushNotifications, emailNotifications, id)
	if err != nil {
		log.Printf("Failed to update user's notification settings. Error: %s", err)
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Failed to get rows affected. Error: %s", err)
		return err
	}
	if rowsAffected == 0 {
		log.Printf("User not found")
		return errors.New(UserNotFoundError)
	}
	return nil
}

func (r *UserRepository) GetUserNotificationSettings(id int64) (bool, bool, error) {
	var pushNotifications, emailNotifications bool
	err := r.db.QueryRow(`SELECT push_notifications, email_notifications FROM users WHERE id=$1`, id).Scan(&pushNotifications, &emailNotifications)
	if err != nil {
		log.Printf("failed to scan row. Error: %s", err)
		return true, true, err
	}
	return pushNotifications, emailNotifications, nil
}

func (r *UserRepository) GetUserType(id int64) (string, error) {
	var userType string
	err := r.db.QueryRow(`SELECT type FROM users WHERE id=$1`, id).Scan(&userType)
	if err != nil {
		log.Printf("failed to scan row. Error: %s", err)
		return "", err
	}
	return strings.ToLower(userType), nil
}

func (r *UserRepository) SetStudentNotificationSettings(id int64, notificationSettings models.StudentNotificationSettingsRequest) error {
	_, err := r.db.Exec(`
		UPDATE students_notifications_settings 
		SET 
		push_enabled = $1,
		email_enabled = $2,
		new_assignment = $3,
		deadline_reminder = $4,
		course_enrollment = $5,
		teacher_feedback = $6,
		grading_available = $7
		WHERE id = $8`,
		notificationSettings.PushEnabled,
		notificationSettings.EmailEnabled,
		notificationSettings.NewAssignment,
		notificationSettings.DeadlineReminder,
		notificationSettings.CourseEnrollment,
		notificationSettings.TeacherFeedback,
		notificationSettings.GradingAvailable,
		id,
	)
	if err != nil {
		log.Printf("Failed to update student notification settings. Error: %s", err)
		return err
	}
	return nil
}

func (r *UserRepository) SetTeacherNotificationSettings(id int64, notificationSettings models.TeacherNotificationSettingsRequest) error {
	_, err := r.db.Exec(`
		UPDATE teachers_notifications_settings 
		SET 
		push_enabled = $1,
		email_enabled = $2,
		assignment_submission = $3,
		student_feedback = $4
		WHERE id = $5`,
		notificationSettings.PushEnabled,
		notificationSettings.EmailEnabled,
		notificationSettings.AssignmentSubmission,
		notificationSettings.StudentFeedback,
		id,
	)
	if err != nil {
		log.Printf("Failed to update teacher notification settings. Error: %s", err)
		return err
	}
	return nil
}

func (r *UserRepository) GetStudentNotificationSettings(id int64) (*models.StudentNotificationSettingsRequest, error) {
	var pushEnabled, emailEnabled bool
	var newAssignment, deadlineReminder, courseEnrollment, teacherFeedback, gradingAvailable models.NotificationPreference
	err := r.db.QueryRow(
		`SELECT 
			push_enabled,
			email_enabled,
			new_assignment,
			deadline_reminder,
			course_enrollment,
			teacher_feedback,
			grading_available
		FROM students_notifications_settings WHERE id=$1`, id,
	).Scan(&pushEnabled, &emailEnabled, &newAssignment, &deadlineReminder, &courseEnrollment, &teacherFeedback, &gradingAvailable)
	if err != nil {
		log.Printf("failed to scan row. Error: %s", err)
		return nil, err
	}
	notificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:      &pushEnabled,
		EmailEnabled:     &emailEnabled,
		NewAssignment:    &newAssignment,
		DeadlineReminder: &deadlineReminder,
		CourseEnrollment: &courseEnrollment,
		TeacherFeedback:  &teacherFeedback,
		GradingAvailable: &gradingAvailable,
	}
	return &notificationSettings, nil
}

func (r *UserRepository) GetTeacherNotificationSettings(id int64) (*models.TeacherNotificationSettingsRequest, error) {
	var pushEnabled, emailEnabled bool
	var assignmentSubmission, studentFeedback models.NotificationPreference
	err := r.db.QueryRow(
		`SELECT 
			push_enabled,
			email_enabled,
			assignment_submission,
			student_feedback
		FROM teachers_notifications_settings WHERE id=$1`, id,
	).Scan(&pushEnabled, &emailEnabled, &assignmentSubmission, &studentFeedback)
	if err != nil {
		log.Printf("failed to scan row. Error: %s", err)
		return nil, err
	}
	notificationSettings := models.TeacherNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		AssignmentSubmission: &assignmentSubmission,
		StudentFeedback:      &studentFeedback,
	}
	return &notificationSettings, nil
}

func (r *UserRepository) ActivateUserEmail(email string) error {
	_, err := r.db.Exec(`UPDATE users SET activated = $1 WHERE email = $2`, true, email)
	if err != nil {
		log.Printf("Failed to activate user email. Error: %s", err)
		return err
	}
	return nil
}
func (r *UserRepository) AddVerificationPin(pin int, email string, expiresAt int) error {
	consumed := false
	query := fmt.Sprintf("INSERT INTO verification_pins VALUES (%d, '%s', %d, %v);", pin, email, expiresAt, consumed)
	_, err := r.db.Exec(query)
	if err != nil {
		log.Printf("Failed to query %s. Error: %s", query, err)
		return err
	}
	return nil
}

func (r *UserRepository) GetPin(pin int, email string) (int, bool, error) {
	var expirationTimestamp int
	var consumed bool
	err := r.db.QueryRow(`SELECT expires_at, consumed FROM verification_pins WHERE pin=$1 AND email=$2`, pin, email).Scan(&expirationTimestamp, &consumed)
	if err != nil && err != sql.ErrNoRows {
		if err == sql.ErrNoRows {
			return 0, false, errors.New(PinNotFoundError)
		}
		log.Printf("failed to scan row. Error: %s", err)
		return 0, false, err
	}
	return expirationTimestamp, consumed, nil
}

func (r *UserRepository) SetPinAsConsumed(pin int, email string) error {
	consumed := true
	_, err := r.db.Exec(`UPDATE verification_pins SET consumed = $1 WHERE pin=$2 AND email=$3`, consumed, pin, email)
	if err != nil {
		log.Printf("Failed to consume pin. Error: %s", err)
		return err
	}
	return nil
}

func (r *UserRepository) UpdateUserPassword(id int, password string) error {
	// Hash the password before storing it
	hasher := sha1.New()
	hasher.Write([]byte(password))
	passwordHash := hex.EncodeToString(hasher.Sum(nil))

	_, err := r.db.Exec(`UPDATE users SET password_hash = $1 WHERE id=$2`, passwordHash, id)
	if err != nil {
		log.Printf("Failed to update user password. Error: %s", err)
		return err
	}
	return nil
}
