package service_test

// import (
// 	"fmt"
// 	"testing"
// 	"user_service/config"
// 	"user_service/mocks"
// 	"user_service/models"
// 	"user_service/service"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// )

// func TestServiceLoginWithRepositoryErrors(t *testing.T) {
// 	loginRequest := models.LoginRequest{
// 		Email:    "john@example.com",
// 		Password: "password",
// 	}
// 	mockError := fmt.Errorf("mock error")
// 	config := config.Config{}
// 	t.Run("Login fails with internal server error when IsEmailRegistered returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.LoginUser(loginRequest)
// 		assert.Equal(t, err, models.InternalServerError())
// 	})

// 	t.Run("Login fails with internal server error when UserBlockedUntil returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
// 		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.LoginUser(loginRequest)
// 		assert.Equal(t, err, models.InternalServerError())
// 	})

// 	t.Run("Login fails with internal server error when PasswordMatches returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
// 		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
// 		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.LoginUser(loginRequest)
// 		assert.Equal(t, err, models.InternalServerError())
// 	})

// 	t.Run("Login fails with internal server error when IncrementFailedLoginAttempts returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
// 		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
// 		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)
// 		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(0), mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.LoginUser(loginRequest)
// 		assert.Equal(t, err, models.InternalServerError())
// 	})

// 	t.Run("Login fails with internal server error when SetUserBlockedUntil returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
// 		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
// 		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)
// 		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(1), nil)
// 		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("1", nil)
// 		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.LoginUser(loginRequest)
// 		assert.Equal(t, err, models.InternalServerError())
// 	})
// }

// func TestServiceRegisterWithRepositoryErrors(t *testing.T) {
// 	user := models.User{}
// 	mockError := fmt.Errorf("mock error")
// 	config := config.Config{}
// 	t.Run("Register fails with internal server error when IsEmailRegistered returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.CreateUser(user)
// 		assert.Equal(t, err, models.InternalServerError())
// 	})

// 	t.Run("Register fails with internal server error when AddUser returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
// 		userRepositoryMock.On("AddUser", mock.Anything).Return(mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.CreateUser(user)
// 		assert.Equal(t, err, models.InternalServerError())
// 	})
// }

// func TestServiceGetUserWithRepositoryErrors(t *testing.T) {
// 	mockError := fmt.Errorf("mock error")
// 	config := config.Config{}
// 	t.Run("Get User fails with internal server error when GetUser returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		_, err = userService.GetUser("1")
// 		assert.Equal(t, err, models.InternalServerError())
// 	})

// 	t.Run("Get Users fails with internal server error when GetUsers returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("GetUsers").Return(nil, mockError)

// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		_, err = userService.GetUsers()
// 		assert.Equal(t, err, models.InternalServerError())
// 	})
// }

// func TestServiceEditUserWithRepositoryErrors(t *testing.T) {
// 	mockError := fmt.Errorf("mock error")
// 	config := config.Config{}

// 	t.Run("Edit user fails with internal server error when repository.UpdateUser returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

// 		editUserRequest := models.EditUserRequest{Name: "Johnny", Email: "johnny@example.com"}
// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		err = userService.EditUser(1, editUserRequest)
// 		expectedError := models.InternalServerError()
// 		assert.Equal(t, expectedError, err)
// 	})
// }

// func TestServiceIsEmailRegisteredWithRepositoryErrors(t *testing.T) {
// 	mockError := fmt.Errorf("mock error")
// 	config := config.Config{}

// 	t.Run("IsEmailRegistered returns internal server error when repository.IsEmailRegistered returns an error", func(t *testing.T) {
// 		userRepositoryMock := new(mocks.Repository)
// 		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)
// 		userService, err := service.NewService(userRepositoryMock, &config)
// 		assert.NoError(t, err)

// 		_, err = userService.IsEmailRegistered("john@example.com")
// 		expectedError := models.InternalServerError()
// 		assert.Equal(t, expectedError, err)
// 	})
// }
