package service_test

import (
	"log"
	"testing"
	"user_service/config"
	"user_service/models"
	"user_service/repository"
	"user_service/service"

	"github.com/stretchr/testify/assert"
)

func TestIntegration(t *testing.T) {
	user := models.User{
		Email:    "john@example.com",
		Name:     "John Doe",
		Password: "password",
		UserType: "alumno",
	}

	config, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config. Error: %s", err)
	}
	userRepository, err := repository.NewUserRepository()
	if err != nil {
		log.Fatalf("Failed to create user repository. Error: %s", err)
	}
	userService, err := service.NewService(userRepository, config)
	if err != nil {
		log.Fatalf("Failed to create user service. Error: %s", err)
	}

	t.Run("user created successfully", func(t *testing.T) {
		err = userService.CreateUser(user)
		assert.NoError(t, err)
	})

	t.Run("user creation fails due to email being already registered", func(t *testing.T) {
		err = userService.CreateUser(user)
		expectedError := models.EmailAlreadyRegisteredError(user.Email)
		assert.Equal(t, expectedError, err)
	})

	t.Run("user logged in successfully", func(t *testing.T) {
		loginRequest := models.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		}
		token, err := userService.LoginUser(loginRequest)
		assert.NoError(t, err)
		assert.NotEqual(t, "", token)
	})

	t.Run("user login fails due to invalid password", func(t *testing.T) {
		loginRequest := models.LoginRequest{
			Email:    user.Email,
			Password: "wrong_password",
		}
		token, err := userService.LoginUser(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)
		assert.NotEqual(t, "", token)
	})
}

// func TestGetUsers(t *testing.T) {
// 	userInfo := models.UserInfo{Id: "1", Name: "John Doe", UserType: "alumno"}
// 	expectedUsers := []models.UserInfo{userInfo}
// 	config := config.Config{}

// 	t.Run("get users succeeds", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("GetUsers").Return(expectedUsers, nil)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		users, err := userService.GetUsers()
// 		assert.NoError(t, err)
// 		assert.Equal(t, expectedUsers, users)
// 		userRepositoryMock.AssertExpectations(t)
// 	})

// 	t.Run("get users fails due to internal server error", func(t *testing.T) {
// 		mockError := fmt.Errorf("mock error")
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("GetUsers").Return(nil, mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		users, err := userService.GetUsers()
// 		expectedError := models.InternalServerError()
// 		assert.Equal(t, expectedError, err)
// 		assert.Nil(t, users)
// 		userRepositoryMock.AssertExpectations(t)
// 	})

// 	t.Run("get user with ID 1 succeeds", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("GetUser", mock.Anything).Return(&userInfo, nil)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		user, err := userService.GetUser("1")
// 		assert.NoError(t, err)
// 		assert.Equal(t, &userInfo, user)
// 		userRepositoryMock.AssertExpectations(t)
// 	})

// 	t.Run("the user with ID 123 was not found", func(t *testing.T) {
// 		id := "123"
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, nil)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		user, err := userService.GetUser(id)
// 		expectedError := models.UserNotFoundError(id)
// 		assert.Equal(t, expectedError, err)
// 		assert.Nil(t, user)
// 		userRepositoryMock.AssertExpectations(t)
// 	})
// }
