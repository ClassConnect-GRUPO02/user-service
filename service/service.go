package service

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math"
	"net/smtp"
	"strconv"
	"time"
	"user_service/auth"
	"user_service/config"
	"user_service/models"
	"user_service/repository"

	expo "github.com/oliveroneill/exponent-server-sdk-golang/sdk"
)

type Service struct {
	userRepository     repository.Repository
	tokenDuration      uint64
	blockingTimeWindow int64
	authService        *auth.Auth
	blockingDuration   int64
	loginAttemptsLimit int64
	email              string
	emailPassword      string
}

func NewService(repository repository.Repository, config *config.Config) (*Service, error) {
	service := Service{
		userRepository:     repository,
		tokenDuration:      config.TokenDuration,
		authService:        &auth.Auth{SecretKey: config.SecretKey},
		blockingTimeWindow: config.BlockingTimeWindow,
		blockingDuration:   config.BlockingDuration,
		loginAttemptsLimit: config.LoginAttemptsLimit,
		email:              config.Email,
		emailPassword:      config.EmailPassword,
	}
	return &service, nil
}

func (s *Service) CreateUser(user models.User) error {
	log.Printf("Creating user %s", user.Email)
	emailAlreadyRegistered, err := s.userRepository.IsEmailRegistered(user.Email)
	if err != nil {
		return models.InternalServerError()
	}
	if emailAlreadyRegistered {
		return models.EmailAlreadyRegisteredError(user.Email)
	}
	err = s.userRepository.AddUser(user)
	if err != nil {
		log.Printf("Failed to add user %v to the database. Error: %s", user, err)
		return models.InternalServerError()
	}
	return nil
}

// Authenticates the user credentials, and returns an error in case of failure
func (s *Service) LoginUser(loginRequest models.LoginRequest) error {
	log.Printf("Authenticating user %s", loginRequest.Email)
	// Check if the email is registered
	emailRegistered, err := s.userRepository.IsEmailRegistered(loginRequest.Email)
	if err != nil {
		return models.InternalServerError()
	}
	if !emailRegistered {
		return models.InvalidCredentialsError()
	}

	// Check if the user is blocked
	blockedUntil, err := s.userRepository.UserBlockedUntil(loginRequest.Email)
	if err != nil {
		return models.InternalServerError()
	}
	timestampNow := time.Now().Unix()
	if blockedUntil > timestampNow {
		return models.UserBlockedError()
	}

	// Check if the password is correct
	passwordMatches, err := s.userRepository.PasswordMatches(loginRequest.Email, loginRequest.Password)
	if err != nil {
		return models.InternalServerError()
	}
	if !passwordMatches {
		// Increment and retrieve the amount of failed login attempts
		failedLoginAttempts, err := s.userRepository.IncrementFailedLoginAttempts(loginRequest.Email, s.blockingTimeWindow)
		if err != nil {
			return models.InternalServerError()
		}
		// If the user reaches the attempts limit, block it
		if failedLoginAttempts >= s.loginAttemptsLimit {
			blockedUntil := time.Now().Unix() + s.blockingDuration
			userId, err := s.userRepository.GetUserIdByEmail(loginRequest.Email)
			if err != nil {
				return models.InternalServerError()
			}
			id, err := strconv.ParseInt(userId, 10, 64)
			if err != nil {
				return models.InternalServerError()
			}
			err = s.userRepository.SetUserBlockedUntil(id, blockedUntil)
			if err != nil {
				return models.InternalServerError()
			}
			return models.UserBlockedError()
		}
		return models.InvalidCredentialsError()
	}

	return nil
}

func (s *Service) GetUsersFullInfo() ([]models.UserFullInfo, error) {
	users, err := s.userRepository.GetUsersFullInfo(s.blockingDuration)
	if err != nil {
		return nil, models.InternalServerError()
	}

	return users, nil
}

func (s *Service) GetUsers() ([]models.UserPublicInfo, error) {
	users, err := s.userRepository.GetUsers()
	if err != nil {
		return nil, models.InternalServerError()
	}

	return users, nil
}

func (s *Service) GetUser(id string) (*models.UserInfo, error) {
	user, err := s.userRepository.GetUser(id)
	if err != nil {
		return nil, models.InternalServerError()
	}
	if user == nil {
		return nil, models.UserNotFoundError(id)
	}
	return user, nil
}

func (s *Service) IssueToken(id string) (string, error) {
	token, err := s.authService.IssueToken(id)
	if err != nil {
		log.Printf("Failed to generate JWT token. Error: %s", err)
		return "", models.InternalServerError()
	}
	return token, nil
}

func (s *Service) GetUserIdByEmail(email string) (string, error) {
	userId, err := s.userRepository.GetUserIdByEmail(email)
	if err != nil {
		return "", models.InternalServerError()
	}
	return userId, nil
}

func (s *Service) EditUser(id int64, newUserData models.EditUserRequest) error {
	err := s.userRepository.UpdateUser(id, newUserData.Name, newUserData.Email)
	if err != nil {
		return models.InternalServerError()
	}
	return nil
}

func (s *Service) IsEmailRegistered(email string) (bool, error) {
	isEmailRegistered, err := s.userRepository.IsEmailRegistered(email)
	if err != nil {
		return false, models.InternalServerError()
	}
	return isEmailRegistered, nil
}

func (s *Service) LoginAdmin(loginRequest models.LoginRequest) error {
	log.Printf("Authenticating user %s", loginRequest.Email)
	// Check if the email is registered
	emailRegistered, err := s.userRepository.IsAdminEmailRegistered(loginRequest.Email)
	if err != nil {
		return models.InternalServerError()
	}
	if !emailRegistered {
		return models.InvalidCredentialsError()
	}

	// Check if the password is correct
	passwordMatches, err := s.userRepository.AdminPasswordMatches(loginRequest.Email, loginRequest.Password)
	if err != nil {
		return models.InternalServerError()
	}
	if !passwordMatches {
		return models.InvalidCredentialsError()
	}

	return nil
}

func (s *Service) GetAdminIdByEmail(email string) (string, error) {
	userId, err := s.userRepository.GetAdminIdByEmail(email)
	if err != nil {
		return "", models.InternalServerError()
	}
	return userId, nil
}

func (s *Service) CreateAdmin(admin models.CreateAdminRequest) error {
	log.Printf("Creating admin %s", admin.Email)
	emailAlreadyRegistered, err := s.userRepository.IsAdminEmailRegistered(admin.Email)
	if err != nil {
		return models.InternalServerError()
	}
	if emailAlreadyRegistered {
		return models.EmailAlreadyRegisteredError(admin.Email)
	}
	err = s.userRepository.AddAdmin(admin.Email, admin.Name, admin.Password)
	if err != nil {
		log.Printf("Failed to add admin %v to the database. Error: %s", admin.Email, err)
		return models.InternalServerError()
	}
	return nil
}

func (s *Service) BlockUser(id int64) error {
	log.Printf("Blocking user %d", id)
	// Block the user permanently
	blockedUntil := int64(math.MaxInt64)
	err := s.userRepository.SetUserBlockedUntil(id, blockedUntil)
	if err != nil {
		return models.InternalServerError()
	}
	return nil
}

func (s *Service) UnblockUser(id int64) error {
	log.Printf("Unblocking user %d", id)
	blockedUntil := int64(0)
	err := s.userRepository.SetUserBlockedUntil(id, blockedUntil)
	if err != nil {
		return models.InternalServerError()
	}
	return nil
}

func (s *Service) SetUserType(id int64, userType string) error {
	log.Printf("Setting user with id %d to %s", id, userType)
	err := s.userRepository.SetUserType(id, userType)
	if err != nil {
		return models.InternalServerError()
	}
	return nil
}

func (s *Service) GetUserType(id int64) (string, error) {
	userType, err := s.userRepository.GetUserType(id)
	if err != nil {
		if err.Error() == UserNotFoundError {
			return "", errors.New(UserNotFoundError)
		}
		return "", models.InternalServerError()
	}
	return userType, nil
}

func (s *Service) SetUserPushToken(id int64, token string) error {
	log.Printf("Setting push token %s to user with id %d ", token, id)
	err := s.userRepository.AddUserPushToken(id, token)
	if err != nil {
		return models.InternalServerError()
	}
	return nil
}

func (s *Service) GetUserPushToken(id int64) (string, error) {
	token, err := s.userRepository.GetUserPushToken(id)
	if err == sql.ErrNoRows {
		return "", errors.New(MissingExpoPushToken)
	}
	if err != nil {
		return "", models.InternalServerError()
	}
	return token, nil
}

func (s *Service) SendPushNotification(token, title, body string) error {
	// Create a new Expo SDK client
	client := expo.NewPushClient(nil)

	// Publish message
	response, err := client.Publish(
		&expo.PushMessage{
			To:       []expo.ExponentPushToken{expo.ExponentPushToken(token)},
			Title:    title,
			Body:     body,
			Data:     map[string]string{"withSome": "data"},
			Sound:    "default",
			Priority: expo.DefaultPriority,
		},
	)
	if err != nil {
		return models.InternalServerError()
	}

	// Validate responses
	err = response.ValidateResponse()
	if err != nil {
		fmt.Printf("failed to send notification to %s. Error: %s", response.PushMessage.To, err)
		return models.InternalServerError()
	}
	return nil
}

func (s *Service) SendEmail(to, subject, body string) error {
	// Gmail SMTP configuration
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	from := s.email
	password := s.emailPassword

	// Authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Email headers and body

	msg := "From: \"ClassConnect\" <" + from + ">\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	// Sending email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("error sending email: %v", err)
	}

	return nil
}

func (s *Service) SetStudentNotificationSettings(id int64, notificationSettings models.StudentNotificationSettingsRequest) error {
	// TODO: validate settings before setting em
	err := s.userRepository.SetStudentNotificationSettings(id, notificationSettings)
	if err != nil && err.Error() == repository.UserNotFoundError {
		return errors.New(UserNotFoundError)
	}
	return err
}

func (s *Service) SetTeacherNotificationSettings(id int64, notificationSettings models.TeacherNotificationSettingsRequest) error {
	// TODO: validate settings before setting em
	err := s.userRepository.SetTeacherNotificationSettings(id, notificationSettings)
	if err != nil && err.Error() == repository.UserNotFoundError {
		return errors.New(UserNotFoundError)
	}
	return err
}

func (s *Service) GetStudentNotificationSettings(id int64) (*models.StudentNotificationSettingsRequest, error) {
	return s.userRepository.GetStudentNotificationSettings(id)
}

func (s *Service) GetTeacherNotificationSettings(id int64) (*models.TeacherNotificationSettingsRequest, error) {
	return s.userRepository.GetTeacherNotificationSettings(id)
}
