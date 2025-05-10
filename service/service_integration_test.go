package service_test

import (
	"log"
	"testing"
	"user_service/config"
	"user_service/models"
	"user_service/repository"
	"user_service/service"
	"user_service/utils"

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
		newName := "Johnny Doe"
		newEmail := "johnny@example.com"
		editUserRequest := models.EditUserRequest{Name: newName, Email: newEmail}
		err := userService.EditUser(id, editUserRequest)
		assert.Nil(t, err)

		user, err := userService.GetUser("1")
		assert.NoError(t, err)
		expectedUser := models.UserInfo{
			Id:        1,
			Name:      newName,  // New name
			Email:     newEmail, // New email
			UserType:  user.UserType,
			Latitude:  user.Latitude,
			Longitude: user.Longitude,
		}
		assert.Equal(t, &expectedUser, user)
	})

	t.Run("check if email exists", func(t *testing.T) {
		isEmailRegistered, err := userService.IsEmailRegistered(user.Email)
		assert.Nil(t, err)
		assert.True(t, isEmailRegistered)
	})

	t.Run("isEmailRegistered on unregistered email returns false", func(t *testing.T) {
		unregisteredEmail := "unregistered@email.com"
		isEmailRegistered, err := userService.IsEmailRegistered(unregisteredEmail)
		assert.Nil(t, err)
		assert.False(t, isEmailRegistered)
	})

	t.Run("admin login with the default account succeeds", func(t *testing.T) {
		loginRequest := models.LoginRequest{Email: "admin", Password: "admin"}
		err := userService.LoginAdmin(loginRequest)
		assert.Nil(t, err)
	})

	t.Run("admin login with an unregistered email returns error", func(t *testing.T) {
		loginRequest := models.LoginRequest{Email: "user", Password: "password"}
		err := userService.LoginAdmin(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)
	})

	t.Run("admin login with wrong password returns error", func(t *testing.T) {
		loginRequest := models.LoginRequest{Email: "admin", Password: "wrong_password"}
		err := userService.LoginAdmin(loginRequest)
		expectedError := models.InvalidCredentialsError()
		assert.Equal(t, expectedError, err)
	})

	t.Run("register admin with valid credentials succeeds", func(t *testing.T) {
		registerRequest := models.CreateAdminRequest{Email: "admin2", Password: "admin2", Name: "admin2"}
		err := userService.CreateAdmin(registerRequest)
		assert.Nil(t, err)
	})

	t.Run("register admin with invalid credentials returns error", func(t *testing.T) {
		alreadyRegisteredEmail := "admin"
		registerRequest := models.CreateAdminRequest{Email: alreadyRegisteredEmail, Password: "admin2", Name: "admin2"}
		err := userService.CreateAdmin(registerRequest)
		expectedError := models.EmailAlreadyRegisteredError(alreadyRegisteredEmail)
		assert.Equal(t, expectedError, err)
	})

	t.Run("get admin id by email succeeds", func(t *testing.T) {
		adminId, err := userService.GetAdminIdByEmail("admin")
		assert.Nil(t, err)
		assert.Equal(t, "1", adminId)
	})

	t.Run("get users full info succeeds", func(t *testing.T) {
		users, err := userService.GetUsersFullInfo()
		assert.Nil(t, err)
		date := utils.GetDate()
		expectedUsers := []models.UserFullInfo{
			{
				Id:               2,
				Name:             "John Doe",
				Email:            "mary@example.com",
				UserType:         "alumno",
				RegistrationDate: date,
				Latitude:         0,
				Longitude:        0,
				Blocked:          false,
			},
			{
				Id:               1,
				Name:             "Johnny Doe",
				Email:            "johnny@example.com",
				UserType:         "alumno",
				RegistrationDate: date,
				Latitude:         0,
				Longitude:        0,
				Blocked:          false,
			},
		}
		assert.Equal(t, expectedUsers, users)
	})

	t.Run("block user succeeds", func(t *testing.T) {
		userId := int64(1)
		err := userService.BlockUser(userId)
		assert.Nil(t, err)
		users, err := userService.GetUsersFullInfo()
		assert.Nil(t, err)
		for _, user := range users {
			if user.Id == int(userId) {
				assert.True(t, user.Blocked)
			}
		}
	})

	t.Run("unblock user succeeds", func(t *testing.T) {
		userId := int64(1)
		err := userService.UnblockUser(userId)
		assert.Nil(t, err)
		users, err := userService.GetUsersFullInfo()
		assert.Nil(t, err)
		for _, user := range users {
			if user.Id == int(userId) {
				assert.False(t, user.Blocked)
			}
		}
	})

	t.Run("set user type succeeds", func(t *testing.T) {
		// Check the user type before updating it
		user, err := userService.GetUser("1")
		assert.Nil(t, err)
		assert.Equal(t, user.UserType, "alumno")

		userId := int64(1)
		userType := "docente"
		// Update user type
		err = userService.SetUserType(userId, userType)
		assert.Nil(t, err)

		// Check the user type has been updated
		user, err = userService.GetUser("1")
		assert.Nil(t, err)
		assert.Equal(t, user.UserType, userType)
	})
}
