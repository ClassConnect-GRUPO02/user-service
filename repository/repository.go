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
	GetUsersFullInfo(blockingDuration int64) ([]models.UserFullInfo, error)
	GetUser(id string) (*models.UserInfo, error)
	GetUserIdByEmail(email string) (string, error)
	IncrementFailedLoginAttempts(email string, blockingTimeWindow int64) (int64, error)
	SetUserBlockedUntil(id int64, timestamp int64) error
	UpdateUser(id int64, name, email string) error
	// Admin methods
	IsAdminEmailRegistered(email string) (bool, error)
	AdminPasswordMatches(email, password string) (bool, error)
	GetAdminIdByEmail(email string) (string, error)
	AddAdmin(email, name, password string) error
	SetUserType(id int64, userType string) error
	AddModificationLog(affectedUserId int64, modification string, date string) error
	GetUserModifications() ([]models.AuditLog, error)
}
