package router_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"user_service/config"
	"user_service/handlers"
	"user_service/mocks"
	"user_service/service"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUserCreation(t *testing.T) {
	config := config.Config{}
	body := `{"name":"John Doe","email":"john@example.com", "userType": "alumno", "password":"1234", "latitude": 10000, "longitude": -10000}`

	// Test valid login
	t.Run("User created successfully ", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddUser", mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/users", handler.CreateUser)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("User creation fails due to email already registered ", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/users", handler.CreateUser)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("User creation fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/users", handler.CreateUser)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Request with missing parameters returns bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/users", handler.CreateUser)

		w := httptest.NewRecorder()
		body := `{"email": "john@example.com"}`
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestUserLogin(t *testing.T) {
	config := config.Config{}
	body := `{"email":"john@example.com", "password":"1234"}`

	// Test valid login
	t.Run("User logged in successfully ", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsBlocked", mock.Anything).Return(false, nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("1", nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/login", handler.HandleLogin)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusAccepted, w.Code)
	})

	t.Run("Login with invalid email fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/login", handler.HandleLogin)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Login with invalid password fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/login", handler.HandleLogin)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Blocked users cannot login", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsBlocked", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/login", handler.HandleLogin)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Login fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/login", handler.HandleLogin)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Request with missing parameters returns bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router := gin.Default()
		router.POST("/login", handler.HandleLogin)

		w := httptest.NewRecorder()
		body := `{"email": "john@example.com"}`
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
