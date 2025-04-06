package service

import (
	"log"
	"user_service/models"
)

type Service struct {
	// TODO: change this to a real database
	database  map[int]models.User
	idCounter int
}

func NewService() *Service {
	service := Service{
		idCounter: 0,
		database:  make(map[int]models.User),
	}
	return &service
}

func (s *Service) CreateUser(user models.User) {
	id := s.idCounter + 1
	log.Printf("Creating user %d", id)
	user.Id = id
	s.database[id] = user
}
