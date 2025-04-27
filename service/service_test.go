package service_test

import (
	"fmt"
	"testing"
	"user_service/config"
	"user_service/mocks"
	"user_service/models"
	"user_service/service"

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
		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(1), nil)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})
}
