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
		Email:     "john@example.com",
		Name:      "John Doe",
		Password:  "password",
		UserType:  "alumno",
		Latitude:  10000,
		Longitude: -10000,
	}

	config, err := config.LoadConfig()
	config.BlockingDuration = 3
	config.BlockingTimeWindow = 1
	config.LoginAttemptsLimit = 3

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
		err := userService.LoginUser(loginRequest)
		assert.NoError(t, err)
	})

	t.Run("user login fails due to invalid email", func(t *testing.T) {
		loginRequest := models.LoginRequest{
			Email:    "wrong_email@example.com",
			Password: user.Password,
		}
		err := userService.LoginUser(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)
	})

	t.Run("user login fails due to invalid password", func(t *testing.T) {
		loginRequest := models.LoginRequest{
			Email:    user.Email,
			Password: "wrong_password",
		}
		err := userService.LoginUser(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)
	})

	t.Run("get users succeeds", func(t *testing.T) {
		users, err := userService.GetUsers()
		assert.NoError(t, err)
		expectedUsers := []models.UserPublicInfo{
			{
				Id:       1,
				Name:     user.Name,
				Email:    user.Email,
				UserType: user.UserType,
			},
		}
		assert.Equal(t, expectedUsers, users)
	})

	t.Run("get user with ID 1", func(t *testing.T) {
		id := "1"
		user, err := userService.GetUser(id)
		assert.NoError(t, err)
		expectedUser := models.UserInfo{
			Id:        1,
			Name:      user.Name,
			Email:     user.Email,
			UserType:  user.UserType,
			Latitude:  user.Latitude,
			Longitude: user.Longitude,
		}
		assert.Equal(t, &expectedUser, user)
	})

	t.Run("get user ID by email", func(t *testing.T) {
		id, err := userService.GetUserIdByEmail(user.Email)
		assert.NoError(t, err)
		expectedId := string("1")
		assert.Equal(t, expectedId, id)
	})

	t.Run("get user with ID 100 was not found", func(t *testing.T) {
		id := "100"
		user, err := userService.GetUser(id)
		expectedError := models.UserNotFoundError(id)
		assert.Equal(t, expectedError, err)
		assert.Nil(t, user)
	})

	t.Run("failed attempts to login block the account", func(t *testing.T) {
		user.Email = "mary@example.com"    // change the user email
		err = userService.CreateUser(user) // register
		assert.Nil(t, err)

		wrongLoginRequest := models.LoginRequest{
			Email:    user.Email,
			Password: "wrong_password",
		}
		expectedError := models.InvalidCredentialsError()

		err := userService.LoginUser(wrongLoginRequest)
		assert.Equal(t, expectedError, err)

		err = userService.LoginUser(wrongLoginRequest)
		assert.Equal(t, expectedError, err)

		expectedError = models.UserBlockedError()
		// At the 3rd attempt, the user should get blocked
		err = userService.LoginUser(wrongLoginRequest)
		assert.Equal(t, expectedError, err)

		// The user should be still blocked
		err = userService.LoginUser(wrongLoginRequest)
		assert.Equal(t, expectedError, err)
	})

	t.Run("edit user succeeds", func(t *testing.T) {
		id := int64(1)
		editUserRequest := models.EditUserRequest{Name: "Johnny Doe", Email: "johnny@example.com"}
		err := userService.EditUser(id, editUserRequest)
		assert.Nil(t, err)
	})
}
