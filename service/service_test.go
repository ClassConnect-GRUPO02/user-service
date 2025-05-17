package service_test

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"user_service/config"
	"user_service/mocks"
	"user_service/models"
	"user_service/repository"
	"user_service/service"
	"user_service/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestServiceLoginWithRepositoryErrors(t *testing.T) {
	loginRequest := models.LoginRequest{
		Email:    "john@example.com",
		Password: "password",
	}
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	t.Run("Login fails with internal server error when IsEmailRegistered returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when UserBlockedUntil returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), mockError)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when PasswordMatches returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, mockError)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when IncrementFailedLoginAttempts returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)
		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(0), mockError)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when SetUserBlockedUntil returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)
		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(1), nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("1", nil)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})
}

func TestServiceRegisterWithRepositoryErrors(t *testing.T) {
	user := models.User{}
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	t.Run("Register fails with internal server error when IsEmailRegistered returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Register fails with internal server error when AddUser returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddUser", mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		assert.Equal(t, err, models.InternalServerError())
	})
}

func TestServiceGetUserWithRepositoryErrors(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	t.Run("Get User fails with internal server error when GetUser returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.GetUser("1")
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Get Users fails with internal server error when GetUsers returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.GetUsers()
		assert.Equal(t, err, models.InternalServerError())
	})
}

func TestServiceEditUserWithRepositoryErrors(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}

	t.Run("Edit user fails with internal server error when repository.UpdateUser returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		editUserRequest := models.EditUserRequest{Name: "Johnny", Email: "johnny@example.com"}
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.EditUser(1, editUserRequest)
		expectedError := models.InternalServerError()
		assert.Equal(t, expectedError, err)
	})
}

func TestServiceIsEmailRegisteredWithRepositoryErrors(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}

	t.Run("IsEmailRegistered returns internal server error when repository.IsEmailRegistered returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.IsEmailRegistered("john@example.com")
		expectedError := models.InternalServerError()
		assert.Equal(t, expectedError, err)
	})
}

func TestServiceGetUserType(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	userId := int64(1)
	t.Run("Get user type succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.NoError(t, err)
		expectedUserType := string(models.Student)
		assert.Equal(t, expectedUserType, userType)
	})

	t.Run("Get user type due to user not found error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), errors.New(service.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.Error(t, err)
		assert.Equal(t, "", userType)
	})

	t.Run("Get user type fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.Error(t, err)
		assert.Equal(t, "", userType)
	})
}

func TestServiceSetUserPushToken(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	mockError := fmt.Errorf("mock error")
	t.Run("Set user push token succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.SetUserPushToken(userId, utils.TEST_PUSH_TOKEN)
		assert.NoError(t, err)
	})

	t.Run("Set user push token fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.SetUserPushToken(userId, utils.TEST_PUSH_TOKEN)
		assert.Error(t, err)
	})
}

func TestServiceGetUserPushToken(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	mockError := fmt.Errorf("mock error")
	t.Run("Get user push token succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.NoError(t, err)
		assert.Equal(t, utils.TEST_PUSH_TOKEN, pushToken)
	})

	t.Run("get user push token fails due to push token not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", sql.ErrNoRows)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.MissingExpoPushToken), err)
		assert.Equal(t, "", pushToken)
	})

	t.Run("get user push token fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.Error(t, err)
		assert.Equal(t, "", pushToken)
	})
}

func TestServiceSendEmail(t *testing.T) {
	emailPassword, err := utils.GetEnvVar("EMAIL_PASSWORD")
	assert.NoError(t, err)
	config := config.Config{
		Email:         "classconnect42@gmail.com",
		EmailPassword: emailPassword,
	}
	t.Run("Send email succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		email := "john@example.com"
		subject := "Running tests"
		body := "Sorry to bother"
		err = userService.SendEmail(email, subject, body)
		assert.NoError(t, err)
	})
}

func TestServiceSetStudentNotificationSettings(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	pushEnabled := true
	emailEnabled := true
	pushAndEmail := models.PushAndEmail
	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		NewAssignment:        &pushAndEmail,
		DeadlineReminder:     &pushAndEmail,
		CourseEnrollment:     &pushAndEmail,
		FavoriteCourseUpdate: &pushAndEmail,
		TeacherFeedback:      &pushAndEmail,
	}

	t.Run("set student notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.SetStudentNotificationSettings(userId, studentNotificationSettings)
		assert.NoError(t, err)
	})

	t.Run("set student notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(errors.New(repository.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.SetStudentNotificationSettings(userId, studentNotificationSettings)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.UserNotFoundError), err)
	})
}
