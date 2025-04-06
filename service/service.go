package service

import (
	"log"
	"user_service/models"
)

type Email = string

type Service struct {
	// TODO: change this to a real database
	database  map[Email]models.User
	idCounter int
}

func NewService() *Service {
	service := Service{
		idCounter: 0,
		database:  make(map[Email]models.User),
	}
	return &service
}

func (s *Service) CreateUser(user models.User) error {
	log.Printf("Creating user %s", user.Email)
	_, emailRegistered := s.database[user.Email]
	if emailRegistered {
		return models.EmailAlreadyRegisteredError(user.Email)
	}
	s.database[user.Email] = user
	return nil
}
