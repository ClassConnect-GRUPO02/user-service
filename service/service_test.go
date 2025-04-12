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

func TestUserCreation(t *testing.T) {
	user := models.User{
		Email:    "john@example.com",
		Name:     "John Doe",
		Password: "password",
		UserType: "alumno",
	}

	config := config.Config{}

	t.Run("user created successfully", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddUser", mock.Anything).Return(nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		err = userService.CreateUser(user)
		assert.NoError(t, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("user creation fails due to email being already registered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		expectedError := models.EmailAlreadyRegisteredError(user.Email)
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("user creation fails due to internal server error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		expectedError := models.InternalServerError()
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})
}

func TestUserLogin(t *testing.T) {
	loginRequest := models.LoginRequest{
		Email:    "john@example.com",
		Password: "password123",
	}
	config := config.Config{}

	t.Run("user logged in successfully", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsBlocked", mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.LoginUser(loginRequest)
		assert.NoError(t, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("user login fails due to invalid password", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.LoginUser(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("user login fails due to invalid email", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.LoginUser(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("blocked user cannot login", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsBlocked", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.LoginUser(loginRequest)
		expectedError := models.UserBlockedError()
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})
}
