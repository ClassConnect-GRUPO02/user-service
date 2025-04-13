package repository

import (
	"user_service/models"
)

type Repository interface {
	IsEmailRegistered(email string) (bool, error)
	AddUser(user models.User) error
	PasswordMatches(email, password string) (bool, error)
	UserIsBlocked(email string) (bool, error)
	GetUsers() ([]models.UserInfo, error)
	GetUser(id string) (*models.UserInfo, error)
	GetUserIdByEmail(email string) (string, error)
}
