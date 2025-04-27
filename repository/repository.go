package repository

import (
	"user_service/models"
)

type Repository interface {
	IsEmailRegistered(email string) (bool, error)
	AddUser(user models.User) error
	PasswordMatches(email, password string) (bool, error)
	UserBlockedUntil(email string) (int64, error)
	GetUsers() ([]models.UserPublicInfo, error)
	GetUser(id string) (*models.UserInfo, error)
	GetUserIdByEmail(email string) (string, error)
	IncrementFailedLoginAttempts(email string, blockingTimeWindow int64) (int64, error)
	SetUserBlockedUntil(email string, timestamp int64) error
}
