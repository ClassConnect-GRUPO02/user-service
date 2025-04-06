package service

import (
	"log"
	"user_service/models"
	"user_service/repository"
)

type Email = string

type Service struct {
	userRepository *repository.UserRepository
	idCounter      int
}

func NewService() *Service {
	service := Service{
		idCounter:      0,
		userRepository: repository.NewUserRepository(),
	}
	return &service
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
	}
	return nil
}
