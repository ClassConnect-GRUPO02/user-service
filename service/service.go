package service

import (
	"log"
	"user_service/auth"
	"user_service/models"
	"user_service/repository"
)

type Service struct {
	userRepository repository.Repository
}

func NewService(repository repository.Repository) (*Service, error) {
	service := Service{
		userRepository: repository,
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

// Authenticates the user credentials, and returns a JWT session token on success
func (s *Service) LoginUser(loginRequest models.LoginRequest) (string, error) {
	log.Printf("Authenticating user %s", loginRequest.Email)
	emailRegistered, err := s.userRepository.IsEmailRegistered(loginRequest.Email)
	if err != nil {
		return "", models.InternalServerError()
	}
	if !emailRegistered {
		return "", models.InvalidCredentialsError()
	}
	passwordMatches, err := s.userRepository.PasswordMatches(loginRequest.Email, loginRequest.Password)
	if err != nil {
		return "", models.InternalServerError()
	}
	if !passwordMatches {
		return "", models.InvalidCredentialsError()
	}
	token, err := auth.IssueToken()
	if err != nil {
		log.Printf("Failed to generate JWT token. Error: %s", err)
		return "", models.InternalServerError()
	}
	return token, nil
}
