package service

import (
	"log"
	"time"
	"user_service/auth"
	"user_service/config"
	"user_service/models"
	"user_service/repository"
)

type Service struct {
	userRepository     repository.Repository
	tokenDuration      uint64
	blockingTimeWindow int64
	authService        *auth.Auth
}

func NewService(repository repository.Repository, config *config.Config) (*Service, error) {
	service := Service{
		userRepository:     repository,
		tokenDuration:      config.TokenDuration,
		authService:        &auth.Auth{SecretKey: config.SecretKey},
		blockingTimeWindow: config.BlockingTimeWindow,
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
		// TODO: extract this variable to the config
		failedLoginAttemptsLimit := int64(5)
		// TODO: extract this to the config
		blockDurationInSeconds := int64(60) // 30 minutes
		failedLoginAttempts, err := s.userRepository.IncrementFailedLoginAttempts(loginRequest.Email, s.blockingTimeWindow)
		if err != nil {
			return models.InternalServerError()
		}
		if failedLoginAttempts >= failedLoginAttemptsLimit {
			blockedUntil := time.Now().Unix() + blockDurationInSeconds
			err := s.userRepository.SetUserBlockedUntil(loginRequest.Email, blockedUntil)
			if err != nil {
				return models.InternalServerError()
			}
			return models.UserBlockedError()
		}
		return models.InvalidCredentialsError()
	}

	return nil
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
