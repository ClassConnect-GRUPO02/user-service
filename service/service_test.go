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
		Email:     "john@example.com",
		Name:      "John Doe",
		Password:  "password",
		UserType:  "alumno",
		Latitude:  10.000,
		Longitude: -10.000,
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

		err = userService.LoginUser(loginRequest)
		assert.NoError(t, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("user login fails due to invalid password", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("user login fails due to invalid email", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
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

		err = userService.LoginUser(loginRequest)
		expectedError := models.UserBlockedError()
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})
}

func TestGetUsers(t *testing.T) {
	userInfo := models.UserInfo{Id: "1", Name: "John Doe", UserType: "alumno", Email: "john@example.com"}
	userPublicInfo := models.UserPublicInfo{Id: "1", Name: "John Doe", UserType: "alumno", Email: "john@example.com"}
	expectedUsers := []models.UserPublicInfo{userPublicInfo}
	config := config.Config{}

	t.Run("get users succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsers").Return(expectedUsers, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		users, err := userService.GetUsers()
		assert.NoError(t, err)
		assert.Equal(t, expectedUsers, users)
		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("get users fails due to internal server error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		users, err := userService.GetUsers()
		expectedError := models.InternalServerError()
		assert.Equal(t, expectedError, err)
		assert.Nil(t, users)
		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("get user with ID 1 succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&userInfo, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		user, err := userService.GetUser("1")
		assert.NoError(t, err)
		assert.Equal(t, &userInfo, user)
		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("the user with ID 123 was not found", func(t *testing.T) {
		id := "123"
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		user, err := userService.GetUser(id)
		expectedError := models.UserNotFoundError(id)
		assert.Equal(t, expectedError, err)
		assert.Nil(t, user)
		userRepositoryMock.AssertExpectations(t)
	})
}
