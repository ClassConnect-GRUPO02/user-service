package service

import (
	"fmt"
	"log"
	"user_service/models"
	"user_service/repository"
)

type Email = string

type Service struct {
	userRepository *repository.UserRepository
	idCounter      int
}

func NewService() (*Service, error) {
	userRepository, err := repository.NewUserRepository()
	if err != nil {
		return nil, fmt.Errorf("failed to create user repository. Error: %s", err)
	}
	service := Service{
		idCounter:      0,
		userRepository: userRepository,
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
