package router_test

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"user_service/config"
	"user_service/handlers"
	"user_service/mocks"
	"user_service/models"
	"user_service/router"
	"user_service/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const TEST_SECRET_KEY = "f1d401c836ec1d97ac4ad9bae38a8963ffc9c495627eff4160102874a5290428bd5ae1d5b6dce8f065e91502e9e722cdd4170c4fb6e3339cd63d9b6bc905c9953c0a8ace2195bb0048c8441a1f9da20b64f222bb9f539acd997d2675bf7bb93f11750abf2a7be29b9d066c064c85f309a5b6735efe3c7d36c6d0c6972f9431a19ec423ea7d6a2991679d33eb0db4992ed0641df243c94bc808a08d1e820bd5a70636fd4aa8a6a4c23f7b32d096e77f81a5ffaf4d9eac6da578326324d62ec5ff418fe5a28adc3751a5fecfb4ecab7ec77ca49e3a6978a56aa557912891291d4f20c2eae0236b074402fb116831dd8a0464ab1510415493b8951d98db4365afac"

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

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

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

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

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

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

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

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email": "john@example.com"}`
		req, _ := http.NewRequest("POST", "/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestUserLogin(t *testing.T) {
	config := config.Config{BlockingDuration: 120}
	body := `{"email":"john@example.com", "password":"1234"}`

	// Test valid login
	t.Run("User logged in successfully", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("1", nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

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

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Login with invalid password fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Blocked users cannot login", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		blockedUntil := time.Now().Unix() + config.BlockingDuration
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(blockedUntil, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Login returns internal server error when GetUserByEmail fails", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("", mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

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

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email": "john@example.com"}`
		req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGetUsers(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	userPublicInfo := models.UserPublicInfo{Id: 1, Name: "John Doe", UserType: "alumno", Email: "john@example.com"}
	expectedUsers := []models.UserPublicInfo{userPublicInfo}

	t.Run("Get users succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsers").Return(expectedUsers, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		token, _ := userService.IssueToken("1")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"users":[{"id":1,"name":"John Doe","email":"john@example.com","userType":"alumno"}]}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Get users returns internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		token, _ := userService.IssueToken("1")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Retrieving the users without Authorization header fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Retrieving the users without JWT token fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Retrieving the users without the 'Bearer' auth header fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "trash")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Retrieving the users with invalid token returns error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalidtoken123")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestGetUser(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	userInfo := models.UserInfo{Id: 1, Name: "John Doe", UserType: "alumno", Email: "john@example.com", Latitude: 10000, Longitude: -10000}

	t.Run("Get user with ID 1 succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&userInfo, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user/1", nil)
		token, _ := userService.IssueToken("2")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"user":{"id":1,"name":"John Doe","email":"john@example.com","userType":"alumno"}}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Get user with same ID as the sender includes private information in the response", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&userInfo, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user/1", nil)
		token, _ := userService.IssueToken("1")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"user":{"id":1,"name":"John Doe","email":"john@example.com","userType":"alumno","latitude":10000,"longitude":-10000}}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Get user fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user/1", nil)
		token, _ := userService.IssueToken("1")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Get user fails if the request does not include the JWT token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user/1", nil)
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
