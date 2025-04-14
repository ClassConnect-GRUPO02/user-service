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
}

// func TestLoginHandler(t *testing.T) {
// 	router := gin.Default()
// 	mockRepos
// 	userService := service.NewService()
// 	handler := handlers.NewUserHandler()
// 	router.POST("/login", h.LoginHandler)

// 	// Test valid login
// 	t.Run("Success", func(t *testing.T) {
// 		body := `{"username":"admin","password":"1234"}`
// 		w := httptest.NewRecorder()
// 		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
// 		req.Header.Set("Content-Type", "application/json")

// 		router.ServeHTTP(w, req)
// 		assert.Equal(t, http.StatusOK, w.Code)
// 		assert.Contains(t, w.Body.String(), "token")
// 	})

// 	// Test invalid login
// 	t.Run("Invalid Password", func(t *testing.T) {
// 		body := `{"username":"admin","password":"wrong"}`
// 		w := httptest.NewRecorder()
// 		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))

// 		router.ServeHTTP(w, req)
// 		assert.Equal(t, http.StatusUnauthorized, w.Code)
// 	})
// }
