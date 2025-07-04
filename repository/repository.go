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
	AddUserPushToken(id int64, token string) error
	GetUserPushToken(id int64) (string, error)
	SetUserNotificationSettings(id int64, pushNotifications bool, emailNotifications bool) error
	GetUserNotificationSettings(id int64) (bool, bool, error)
	GetUserType(id int64) (string, error)
	SetStudentNotificationSettings(id int64, notificationSettings models.StudentNotificationSettingsRequest) error
	SetTeacherNotificationSettings(id int64, notificationSettings models.TeacherNotificationSettingsRequest) error
	GetStudentNotificationSettings(id int64) (*models.StudentNotificationSettingsRequest, error)
	GetTeacherNotificationSettings(id int64) (*models.TeacherNotificationSettingsRequest, error)
	UserIsActivated(email string) (bool, error)
	ActivateUserEmail(email string) error
	AddVerificationPin(pin int, email string, expiresAt int) error
	GetPin(pin int, email string) (int, bool, error)
	SetPinAsConsumed(pin int, email string) error
	UpdateUserPassword(id int, password string) error
	LinkGoogleEmail(email string) error
	IsEmailLinkedToGoogleAccount(email string) (bool, error)

	// Admin methods
	IsAdminEmailRegistered(email string) (bool, error)
	AdminPasswordMatches(email, password string) (bool, error)
	GetAdminIdByEmail(email string) (string, error)
	AddAdmin(email, name, password string) error
	SetUserType(id int64, userType string) error
	AddModificationLog(affectedUserId int64, modification string, date string) error
}
