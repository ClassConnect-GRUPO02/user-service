package repository

import (
	"user_service/models"
)

type Repository interface {
	IsEmailRegistered(email string) (bool, error)
	AddUser(user models.User) error
}
