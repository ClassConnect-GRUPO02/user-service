package service_test

import (
	"fmt"
	"testing"
	"user_service/mocks"
	"user_service/models"
	"user_service/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUserService(t *testing.T) {
	user := models.User{
		Email:    "john@example.com",
		Name:     "John Doe",
		Password: "password",
		UserType: "alumno",
	}
	t.Run("user created successfully", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddUser", mock.Anything).Return(nil)

		userService, err := service.NewService(userRepositoryMock)
		assert.NoError(t, err)
		err = userService.CreateUser(user)
		assert.NoError(t, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("email already registered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		expectedError := models.EmailAlreadyRegisteredError(user.Email)
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})

	t.Run("internal server error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		userService, err := service.NewService(userRepositoryMock)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		expectedError := models.InternalServerError()
		assert.Equal(t, expectedError, err)

		userRepositoryMock.AssertExpectations(t)
	})
}
