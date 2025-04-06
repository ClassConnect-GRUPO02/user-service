package service

import (
	"log"
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
