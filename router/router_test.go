package router_test

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"user_service/auth"
	"user_service/config"
	"user_service/handlers"
	"user_service/mocks"
	"user_service/models"
	"user_service/repository"
	"user_service/router"
	"user_service/service"
	"user_service/utils"

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
		userRepositoryMock.On("AddVerificationPin", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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
	config := config.Config{BlockingDuration: 120, LoginAttemptsLimit: 5}
	body := `{"email":"john@example.com", "password":"1234"}`
	studentUserType := "alumno"

	// Test valid login
	t.Run("User logged in successfully", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("1", nil)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)
		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(1), nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)
		blockedUntil := time.Now().Unix() + config.BlockingDuration
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(blockedUntil, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("", mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		token, _ := userService.IssueToken("1", "alumno")
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		token, _ := userService.IssueToken("1", "alumno")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Retrieving the users without Authorization header fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

	t.Run("Get users with admin token returns the full users info", func(t *testing.T) {
		usersFullInfo := []models.UserFullInfo{
			{
				Id:               1,
				Name:             "John Doe",
				UserType:         "alumno",
				Email:            "john@example.com",
				Blocked:          false,
				RegistrationDate: "2025-04-10",
				Latitude:         123123,
				Longitude:        123123,
			},
		}
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsersFullInfo", mock.Anything).Return(usersFullInfo, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"users":[{"id":1,"name":"John Doe","email":"john@example.com","userType":"alumno","registrationDate":"2025-04-10","latitude":123123,"longitude":123123,"blocked":false}]}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Get users with admin token returns error when the repository fails", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsersFullInfo", mock.Anything).Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestGetUser(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	userInfo := models.UserInfo{Id: 1, Name: "John Doe", UserType: "alumno", Email: "john@example.com", Latitude: 10000, Longitude: -10000}

	t.Run("Get user with ID 1 succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&userInfo, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user/1", nil)
		token, _ := userService.IssueToken("2", "alumno")
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user/1", nil)
		token, _ := userService.IssueToken("1", "alumno")
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

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user/1", nil)
		token, _ := userService.IssueToken("1", "alumno")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Get user fails if the request does not include the JWT token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
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

func TestEditUser(t *testing.T) {
	config := config.Config{TokenDuration: 300}
	body := `{"name":"Johnny Doe","email":"john@example.com"}`

	t.Run("Edit user with ID 1 succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		token, _ := userService.IssueToken("1", "alumno")
		req, _ := http.NewRequest("PUT", "/user/1", strings.NewReader(body))

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"description":"User updated successfully"}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Edit user without JWT token returns BadRequest error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Edit user with non numeric ID returns BadRequest error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		token, _ := userService.IssueToken("1", "alumno")
		req, _ := http.NewRequest("PUT", "/user/abc", strings.NewReader(body))

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid id: abc","instance":"/user/abc"}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Edit user returns InternalServerError when repository fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("Mock error")
		userRepositoryMock.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		token, _ := userService.IssueToken("1", "alumno")
		req, _ := http.NewRequest("PUT", "/user/1", strings.NewReader(body))

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Edit user with missing parameters returns error", func(t *testing.T) {
		bodyWithMissingParameters := `{"name": "John"}` // missing email
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("Mock error")
		userRepositoryMock.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		token, _ := userService.IssueToken("1", "alumno")
		req, _ := http.NewRequest("PUT", "/user/1", strings.NewReader(bodyWithMissingParameters))

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/user/1"}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Edit user with a JWT token from other user returns error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		token, _ := userService.IssueToken("1", "alumno")
		req, _ := http.NewRequest("PUT", "/user/2", strings.NewReader(body))

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		expectedBody := `{"type":"about:blank","title":"Invalid token","status":401,"detail":"The given JWT token is invalid","instance":""}`

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, expectedBody, w.Body.String())
	})
}

func TestCheckEmailExists(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	email := "john@example.com"
	id := "1"
	studentUserType := "student"

	t.Run("Check email exists", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return(id, nil)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/check-email-exists/"+email, nil)
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		response := w.Body.String()
		emailExists := strings.Contains(response, `"exists":true`)
		responseContainsToken := strings.Contains(response, `"token":`)
		responseContainsId := strings.Contains(response, `"id":`)

		assert.True(t, emailExists)
		assert.True(t, responseContainsToken)
		assert.True(t, responseContainsId)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Check email exists returns false when the email does not exist", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/check-email-exists/"+email, nil)
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		response := w.Body.String()
		emailExists := strings.Contains(response, `"exists":false`)
		responseContainsToken := strings.Contains(response, `"token":`)

		assert.True(t, emailExists)
		// The endpoint should not return the token on unregistered emails
		assert.False(t, responseContainsToken)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	mockError := fmt.Errorf("mock error")

	t.Run("Check email exists returns InternalServerError when repository.IsEmailRegistered returns error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/check-email-exists/"+email, nil)
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Check email exists returns InternalServerError when repository.GetUserIdByEmail returns error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("", mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/check-email-exists/"+email, nil)
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestAdminLogin(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}

	t.Run("Admin login succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("AdminPasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetAdminIdByEmail", mock.Anything).Return("1", nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admin-login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusAccepted, w.Code)
	})

	t.Run("Admin login fails with bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"password":"admin"}`
		req, _ := http.NewRequest("POST", "/admin-login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Admin login fails due to invalid email", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(false, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admin-login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Admin login fails due to invalid password", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("AdminPasswordMatches", mock.Anything, mock.Anything).Return(false, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admin-login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Admin login fails due to internal server error in repository.IsAdminEmailRegistered", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(false, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admin-login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Admin login fails due to internal server error in repository.AdminPasswordMatches", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("AdminPasswordMatches", mock.Anything, mock.Anything).Return(false, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admin-login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Admin login fails due to internal server error in repository.GetAdminIdByEmailgs", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("AdminPasswordMatches", mock.Anything, mock.Anything).Return(true, nil)
		userRepositoryMock.On("GetAdminIdByEmail", mock.Anything).Return("", mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admin-login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestAdminRegister(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}

	t.Run("Admin register succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddAdmin", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","name":"admin","password":"admin"}`
		token, _ := userService.IssueToken("1", "admin")
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("Admin register fails with bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"password":"admin"}`
		token, _ := userService.IssueToken("1", "admin")
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Admin register fails due to email already registered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(true, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","name":"admin","password":"admin"}`
		token, _ := userService.IssueToken("1", "admin")
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("Admin register fails due to missing token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(true, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","name":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Admin register fails due to invalid token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(true, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","name":"admin","password":"admin"}`
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalid_token")

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	mockError := fmt.Errorf("mock error")

	t.Run("Admin register fails due to internal server error in repository.IsAdminEmailRegistered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(false, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","name":"admin","password":"admin"}`
		token, _ := userService.IssueToken("1", "admin")
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Admin register fails due to internal server error in repository.AddAdmin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddAdmin", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","name":"admin","password":"admin"}`
		token, _ := userService.IssueToken("1", "admin")
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Admin register when the token is not from an admin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsAdminEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddAdmin", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"email":"admin","name":"admin","password":"admin"}`
		token, _ := userService.IssueToken("1", "alumno")
		req, _ := http.NewRequest("POST", "/admins", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestBlockUser(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	id := "1"

	t.Run("Block user succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(nil)
		userRepositoryMock.On("AddModificationLog", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/block", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		response := w.Body.String()
		expectedResponse := `{"blocked":true,"description":"User blocked successfully","id":"1"}`

		assert.Equal(t, expectedResponse, response)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Block user fails when the given token is not from an admin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/block", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "alumno")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Block user fails with InternalServerError repository.SetUserBlockedUntil returns an error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/block", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Block user fails with InternalServerError repository.AddModificationLog returns an error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(nil)
		userRepositoryMock.On("AddModificationLog", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/block", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("admin", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Block user fails with BadRequest when the id is invalid", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		wrongId := "abc"
		req, _ := http.NewRequest("PUT", "/user/"+wrongId+"/block", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Block user fails with InvalidToken when the token is invalid", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/block", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalidToken")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestUnblockUser(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	id := "1"

	t.Run("Unblock user succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(nil)
		userRepositoryMock.On("AddModificationLog", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/unblock", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		response := w.Body.String()
		expectedResponse := `{"blocked":false,"description":"User unblocked successfully","id":"1"}`

		assert.Equal(t, expectedResponse, response)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Unblock user fails when the given token is not from an admin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/unblock", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "alumno")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Unblock user with bad request when the id is invalid", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		wrongId := "abc"
		req, _ := http.NewRequest("PUT", "/user/"+wrongId+"/unblock", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Unblock user with bad request when the token is invalid", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/unblock", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalidToken")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Unblock user fails with InternalServerError repository.SetUserBlockedUntil returns an error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/unblock", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Unblock user fails with InternalServerError repository.AddModificationLog returns an error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(nil)
		userRepositoryMock.On("AddModificationLog", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/user/"+id+"/unblock", nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("admin", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestSetUserType(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	id := "1"

	t.Run("Set user type succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserType", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		userRepositoryMock.On("AddModificationLog", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		userType := "docente"
		req, _ := http.NewRequest("PUT", "/user/"+id+"/type/"+userType, nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)
		response := w.Body.String()
		expectedResponse := `{"description":"User type updated successfully","id":"1","userType":"docente"}`

		assert.Equal(t, expectedResponse, response)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Set user type fails when the token is not from an admin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserType", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		userType := "docente"
		req, _ := http.NewRequest("PUT", "/user/"+id+"/type/"+userType, nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "alumno")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Set user type fails when the token is invalid", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserType", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		userType := "docente"
		req, _ := http.NewRequest("PUT", "/user/"+id+"/type/"+userType, nil)
		req.Header.Set("Content-Type", "application/json")
		invalidToken := "abc"
		req.Header.Set("Authorization", "Bearer "+invalidToken)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Set user type fails when the user id is invalid", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserType", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		userType := "docente"
		wrongId := "abc"
		req, _ := http.NewRequest("PUT", "/user/"+wrongId+"/type/"+userType, nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Set user type fails when the user the repository returns an error", func(t *testing.T) {
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetUserType", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		userType := "docente"
		req, _ := http.NewRequest("PUT", "/user/"+id+"/type/"+userType, nil)
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken("1", "admin")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestAddPushToken(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	id := "1"
	mockError := fmt.Errorf("mock error")
	t.Run("Add push token succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"token":"ExponentPushToken[**************]"}`
		req, _ := http.NewRequest("POST", "/users/"+id+"/push-token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken(id, "alumno")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Add push token fails due to invalid id", func(t *testing.T) {
		invalidId := "abc"
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		body := `{"token":"ExponentPushToken[**************]"}`
		req, _ := http.NewRequest("POST", "/users/"+invalidId+"/push-token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken(invalidId, "alumno")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid id: abc","instance":"/users/abc/push-token"}`
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Add push token fails due to bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		handler := handlers.NewUserHandler(userService)

		router, err := router.CreateUserRouter(handler)
		assert.NoError(t, err)

		w := httptest.NewRecorder()
		emptyBody := "{}"
		req, _ := http.NewRequest("POST", "/users/"+id+"/push-token", strings.NewReader(emptyBody))
		req.Header.Set("Content-Type", "application/json")
		token, _ := userService.IssueToken(id, "alumno")
		req.Header.Set("Authorization", "Bearer "+token)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/1/push-token"}`
		assert.Equal(t, expectedBody, w.Body.String())
	})

	t.Run("Add push token fails due to invalid expo token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		body := "{}"
		request := NewRequest(
			"POST",
			"/users/"+id+"/push-token",
			body,
			Header("Content-Type", "application/json"),
			Header("Authorization", "Bearer "+token),
		)
		statusCode, responseBody, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusBadRequest, statusCode)
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/1/push-token"}`
		assert.Equal(t, expectedBody, responseBody)
	})

	t.Run("Add push token fails due to invalid expo token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		body := `{"token": "invalidExpoToken"}`
		request := NewRequest(
			"POST",
			"/users/"+id+"/push-token",
			body,
			Header("Content-Type", "application/json"),
			Header("Authorization", "Bearer "+token),
		)
		statusCode, responseBody, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, statusCode)
		expectedBody := `{"type":"about:blank","title":"Invalid expo token","status":401,"detail":"The expo token 'invalidExpoToken' is invalid","instance":"/users/1/push-token"}`
		assert.Equal(t, expectedBody, responseBody)
	})

	t.Run("Add push token fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		body := `{"token": "ExponentPushToken[*************]"}`
		request := NewRequest(
			"POST",
			"/users/"+id+"/push-token",
			body,
			Header("Content-Type", "application/json"),
			Header("Authorization", "Bearer "+token),
		)
		statusCode, responseBody, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusInternalServerError, statusCode)
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		assert.Equal(t, expectedBody, responseBody)
	})

	t.Run("Add push token fails when the JWT token does not match the user id", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken("3", "alumno")
		assert.NoError(t, err)
		body := `{"token": "ExponentPushToken[*************]"}`
		request := NewRequest(
			"POST",
			"/users/"+id+"/push-token",
			body,
			Header("Content-Type", "application/json"),
			Header("Authorization", "Bearer "+token),
		)
		statusCode, responseBody, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, statusCode)
		expectedBody := `{"type":"about:blank","title":"Invalid token","status":401,"detail":"The given JWT token is invalid","instance":""}`
		assert.Equal(t, expectedBody, responseBody)
	})
}

func TestSetUserNotificationSettings(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	id := "1"
	mockError := fmt.Errorf("mock error")
	pushEnabled := true
	emailEnabled := true
	// push := models.Push
	// email := models.Email
	pushAndEmail := models.PushAndEmail
	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:      &pushEnabled,
		EmailEnabled:     &emailEnabled,
		NewAssignment:    &pushAndEmail,
		DeadlineReminder: &pushAndEmail,
		CourseEnrollment: &pushAndEmail,
		TeacherFeedback:  &pushAndEmail,
		GradingAvailable: &pushAndEmail,
	}
	teacherNotificationSettings := models.TeacherNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		AssignmentSubmission: &pushAndEmail,
		StudentFeedback:      &pushAndEmail,
		CourseAssigned:       &pushAndEmail,
		CourseRevoked:        &pushAndEmail,
	}
	studentUserType := "alumno"
	teacherUserType := "docente"

	t.Run("Set student notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		body, _ := json.Marshal(studentNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Notification settings updated successfully","id":1}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set student notification settings fails due to invalid request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		body, _ := json.Marshal(teacherNotificationSettings) // use teacher notification settings
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/1/notification-settings"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set student notification settings fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		body, _ := json.Marshal(studentNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set teacher notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(teacherUserType, nil)
		userRepositoryMock.On("SetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "docente")
		assert.NoError(t, err)
		body, _ := json.Marshal(teacherNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Notification settings updated successfully","id":1}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set teacher notification settings fails due to bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(teacherUserType, nil)
		userRepositoryMock.On("SetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "docente")
		assert.NoError(t, err)
		body, _ := json.Marshal(studentNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/1/notification-settings"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set user notification settings fails due invalid jwt token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		invalidToken := "invalid token"
		assert.NoError(t, err)
		body, _ := json.Marshal(studentNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), invalidToken)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid token","status":401,"detail":"The given JWT token is invalid","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set user notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return("", errors.New(service.UserNotFoundError))
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "docente")
		assert.NoError(t, err)
		body, _ := json.Marshal(studentNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusNotFound
		expectedBody := `{"type":"about:blank","title":"User not found","status":404,"detail":"The user with id 1 was not found","instance":"/user/1"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set user notification settings fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return("", mockError)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "docente")
		assert.NoError(t, err)
		body, _ := json.Marshal(studentNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Set user notification settings fails due to mismatching JWT token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return("", mockError)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken("3", "docente")
		assert.NoError(t, err)
		body, _ := json.Marshal(studentNotificationSettings)
		request := PutUserNotificationSettingsReq(id, string(body), token)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid token","status":401,"detail":"The given JWT token is invalid","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})
}

func TestGetUserNotificationSettings(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	id := "1"
	mockError := fmt.Errorf("mock error")
	pushEnabled := true
	emailEnabled := true
	pushAndEmail := models.PushAndEmail

	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:      &pushEnabled,
		EmailEnabled:     &emailEnabled,
		NewAssignment:    &pushAndEmail,
		DeadlineReminder: &pushAndEmail,
		CourseEnrollment: &pushAndEmail,
		TeacherFeedback:  &pushAndEmail,
		GradingAvailable: &pushAndEmail,
	}
	teacherNotificationSettings := models.TeacherNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		AssignmentSubmission: &pushAndEmail,
		StudentFeedback:      &pushAndEmail,
		CourseAssigned:       &pushAndEmail,
		CourseRevoked:        &pushAndEmail,
	}
	studentUserType := "alumno"
	teacherUserType := "docente"

	t.Run("Get student notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything).Return(&studentNotificationSettings, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)

		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusOK
		expectedBody, _ := json.Marshal(studentNotificationSettings)
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get teacher notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(teacherUserType, nil)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything).Return(&teacherNotificationSettings, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)

		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusOK
		expectedBody, _ := json.Marshal(teacherNotificationSettings)
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get user notification settings fails due to invalid token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		invalidToken := "invalid token"
		assert.NoError(t, err)

		request := GetUserNotificationSettingsReq(id, "", invalidToken)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid token","status":401,"detail":"The given JWT token is invalid","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get user notification settings fails due to invalid id", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		invalidId := "abc"
		request := GetUserNotificationSettingsReq(invalidId, "", token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid id: abc","instance":"/users/abc/notification-settings"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get user notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return("", errors.New(service.UserNotFoundError))
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusNotFound
		expectedBody := `{"type":"about:blank","title":"User not found","status":404,"detail":"The user with id 1 was not found","instance":"/user/1"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get user notification settings fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return("", mockError)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get student notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything).Return(nil, errors.New(service.UserNotFoundError))

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusNotFound
		expectedBody := `{"type":"about:blank","title":"User not found","status":404,"detail":"The user with id 1 was not found","instance":"/user/1"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get student notification settings fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentUserType, nil)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything).Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get teacher notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(teacherUserType, nil)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything).Return(nil, errors.New(service.UserNotFoundError))

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusNotFound
		expectedBody := `{"type":"about:blank","title":"User not found","status":404,"detail":"The user with id 1 was not found","instance":"/user/1"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get teacher notification settings fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(teacherUserType, nil)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything).Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Get user notification settings fails due to mismatching JWT token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return("", errors.New(service.UserNotFoundError))
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken("3", "alumno") // use token of other user
		assert.NoError(t, err)
		request := GetUserNotificationSettingsReq(id, "", token)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid token","status":401,"detail":"The given JWT token is invalid","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})
}

func TestNotifyUser(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	id := "1"
	mockError := fmt.Errorf("mock error")
	pushEnabled := true
	emailEnabled := true
	pushAndEmail := models.PushAndEmail

	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:      &pushEnabled,
		EmailEnabled:     &emailEnabled,
		NewAssignment:    &pushAndEmail,
		DeadlineReminder: &pushAndEmail,
		CourseEnrollment: &pushAndEmail,
		TeacherFeedback:  &pushAndEmail,
		GradingAvailable: &pushAndEmail,
	}
	teacherNotificationSettings := models.TeacherNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		AssignmentSubmission: &pushAndEmail,
		StudentFeedback:      &pushAndEmail,
		CourseAssigned:       &pushAndEmail,
		CourseRevoked:        &pushAndEmail,
	}
	studentUserType := "alumno"
	teacherUserType := "docente"

	student := models.UserInfo{
		Email:    utils.TEST_EMAIL,
		UserType: studentUserType,
	}

	teacher := models.UserInfo{
		Email:    utils.TEST_EMAIL,
		UserType: teacherUserType,
	}

	t.Run("Notify student succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&student, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything).Return(&studentNotificationSettings, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.NewAssignment)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Notification scheduled","email":"test@email.com","id":"1"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify student succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&teacher, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything).Return(&teacherNotificationSettings, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.StudentFeedback)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Notification scheduled","email":"test@email.com","id":"1"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify user fails due to invalid id", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.StudentFeedback)
		invalidId := "abc"
		request := NotifyUserReq(invalidId, requestBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid id: abc","instance":"/users/abc/notifications"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify user fails due to bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := "{}" // invalid body
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/1/notifications"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify user fails due to internal server error on repository.GetUser", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.StudentFeedback)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify user fails due to missing expo push token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&student, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", sql.ErrNoRows)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.StudentFeedback)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusNotFound
		expectedBody := `{"type":"about:blank","title":"Missing expo push token","status":404,"detail":"The user 1 is missing an Expo push token","instance":"/users/1/notifications"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify user fails due to internal server error on repository.GetUserPushToken", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&student, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.StudentFeedback)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify student fails due to internal server error on repository.GetStudentNotificationSettings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&student, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything).Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.StudentFeedback)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify student fails due to invalid notification type", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&student, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything).Return(&studentNotificationSettings, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		invalidNotificationType := "abc"
		requestBody := NotificationRequestBodyWithType(invalidNotificationType)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid notification type: abc","instance":"/users/1/notifications"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify teacher fails due to internal server error on repository.GetStudentNotificationSettings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&teacher, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything).Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody := NotificationRequestBodyWithType(models.StudentFeedback)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify teacher fails due to invalid notification type", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&teacher, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything).Return(&teacherNotificationSettings, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		invalidNotificationType := "abc"
		requestBody := NotificationRequestBodyWithType(invalidNotificationType)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid notification type: abc","instance":"/users/1/notifications"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Notify user fails due to invalid user type", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		userRepositoryMock.On("GetUser", mock.Anything).Return(&models.UserInfo{}, nil)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything).Return(&teacherNotificationSettings, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		invalidNotificationType := "abc"
		requestBody := NotificationRequestBodyWithType(invalidNotificationType)
		request := NotifyUserReq(id, requestBody, token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})
}

func TestBiometricLogin(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey, RefreshTokenDuration: 300}
	id := "1"
	studentUserType := "alumno"
	user := models.UserInfo{Email: utils.TEST_EMAIL}
	mockError := fmt.Errorf("mock error")

	t.Run("Biometric login succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&user, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, studentUserType)
		assert.NoError(t, err)
		refreshToken, err := userService.IssueRefreshToken(id)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.BiometricLoginRequest{RefreshToken: refreshToken})
		request := BiometricLoginReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusAccepted
		statusCode, _, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)
		assert.Equal(t, expectedStatusCode, statusCode)
	})

	t.Run("Biometric login fails due to bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, studentUserType)
		assert.NoError(t, err)
		invalidBody := "{}"
		request := BiometricLoginReq(id, invalidBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/biometric-login"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Biometric login fails due to invalid refresh token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, studentUserType)
		assert.NoError(t, err)
		body := `{"token": "invalid refresh token"}`
		request := BiometricLoginReq(id, body, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/biometric-login"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, string(expectedBody))
	})

	t.Run("Biometric login fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, studentUserType)
		assert.NoError(t, err)
		refreshToken, err := userService.IssueRefreshToken(id)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.BiometricLoginRequest{RefreshToken: refreshToken})
		request := BiometricLoginReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusNotFound
		statusCode, _, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)
		assert.Equal(t, expectedStatusCode, statusCode)
	})

	t.Run("Biometric login fails due to internal server error on repository.GetUser", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, studentUserType)
		assert.NoError(t, err)
		refreshToken, err := userService.IssueRefreshToken(id)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.BiometricLoginRequest{RefreshToken: refreshToken})
		request := BiometricLoginReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusInternalServerError
		statusCode, _, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)
		assert.Equal(t, expectedStatusCode, statusCode)
	})

	t.Run("Biometric login fails due to blocked user", func(t *testing.T) {
		blockedUntil := time.Now().Unix() + int64(300)
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&user, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(blockedUntil, nil)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, studentUserType)
		assert.NoError(t, err)
		refreshToken, err := userService.IssueRefreshToken(id)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.BiometricLoginRequest{RefreshToken: refreshToken})
		request := BiometricLoginReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusForbidden
		expectedBody := `{"type":"about:blank","title":"The account is blocked","status":403,"detail":"The given account is currently blocked and is not authorized to log in.","instance":"/login"}`
		statusCode, responseBody, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)
		assert.Equal(t, expectedStatusCode, statusCode)
		assert.Equal(t, expectedBody, responseBody)
	})

	t.Run("Biometric login fails due to internal server error on repository.UserBlockedUntil", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(&user, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), mockError)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, studentUserType)
		assert.NoError(t, err)
		refreshToken, err := userService.IssueRefreshToken(id)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.BiometricLoginRequest{RefreshToken: refreshToken})
		request := BiometricLoginReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusInternalServerError
		statusCode, _, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)
		assert.Equal(t, expectedStatusCode, statusCode)
	})
}

func TestVerifyUserEmail(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey, RefreshTokenDuration: 300}
	id := "1"
	mockError := fmt.Errorf("mock error")

	t.Run("Verify user email succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := int(time.Now().Unix() + 300)
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)
		userRepositoryMock.On("SetPinAsConsumed", mock.Anything, mock.Anything).Return(nil)
		userRepositoryMock.On("ActivateUserEmail", mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.EmailVerificationRequest{Email: utils.TEST_EMAIL, Pin: 99999})
		request := VerifyUserEmailReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Email verified successfully","email":"test@email.com"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Verify user email fails due to invalid request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		invalidBody := "{}"
		request := VerifyUserEmailReq(id, invalidBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/verify"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Verify user fails due to pin not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(0, false, errors.New(repository.PinNotFoundError))

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.EmailVerificationRequest{Email: utils.TEST_EMAIL, Pin: 99999})
		request := VerifyUserEmailReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid PIN","status":401,"detail":"The verification PIN 99999 is invalid","instance":"/users/verify"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Verify user email fails due to pin already consumed", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := int(time.Now().Unix() + 300)
		consumed := true // Pin consumed
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.EmailVerificationRequest{Email: utils.TEST_EMAIL, Pin: 99999})
		request := VerifyUserEmailReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid PIN","status":401,"detail":"The verification PIN 99999 is invalid","instance":"/users/verify"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Verify user email fails due to expired pin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := 0
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.EmailVerificationRequest{Email: utils.TEST_EMAIL, Pin: 99999})
		request := VerifyUserEmailReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid PIN","status":401,"detail":"The verification PIN 99999 is invalid","instance":"/users/verify"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Verify user email fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := 0
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.EmailVerificationRequest{Email: utils.TEST_EMAIL, Pin: 99999})
		request := VerifyUserEmailReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})
}

func TestRequestNewPin(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey, RefreshTokenDuration: 300}
	id := "1"

	t.Run("Request new pin succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddVerificationPin", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.RequestNewVerificationPin{Email: utils.TEST_EMAIL})
		request := RequestNewPinReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Verification PIN sent to email","email":"test@email.com"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Request new pin fails due to invalid request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		invalidBody := "{}"
		request := RequestNewPinReq(id, invalidBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/request-new-pin"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})
	t.Run("Request new pin fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddVerificationPin", mock.Anything, mock.Anything, mock.Anything).Return(errors.New(service.InternalServerError))

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.RequestNewVerificationPin{Email: utils.TEST_EMAIL})
		request := RequestNewPinReq(id, string(requestBody), token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})
}

func TestResetPassword(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey, RefreshTokenDuration: 300, ResetPasswordTokenDuration: 60}
	id := "1"

	t.Run("Reset password succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UpdateUserPassword", mock.Anything, mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ResetPasswordRequest{NewPassword: "newpassword"})
		request := ResetPasswordReq(string(requestBody), token)
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Password reset successfully"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Reset password fails due to bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		invalidBody := "{}"
		request := ResetPasswordReq(invalidBody, token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/reset-password"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Reset password fails due to invalid JWT token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		invalidToken := "invalid token"
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ResetPasswordRequest{NewPassword: "newpassword"})
		request := ResetPasswordReq(string(requestBody), invalidToken)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Invalid token","status":401,"detail":"The given JWT token is invalid","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Reset password fails due to invalid id", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		invalidId := "abc"
		token, err := userService.IssueToken(invalidId, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ResetPasswordRequest{NewPassword: "newpassword"})
		request := ResetPasswordReq(string(requestBody), token)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"Invalid id: abc","instance":"/users/reset-password"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Reset password fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("UpdateUserPassword", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ResetPasswordRequest{NewPassword: "newpassword"})
		request := ResetPasswordReq(string(requestBody), token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Reset password fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("UpdateUserPassword", mock.Anything, mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ResetPasswordRequest{NewPassword: "newpassword"})
		request := ResetPasswordReq(string(requestBody), token)
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Reset password fails due to expired token", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UpdateUserPassword", mock.Anything, mock.Anything).Return(nil)
		config.ResetPasswordTokenDuration = 0 // Set token duration to 0
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		token, err := userService.IssueToken(id, "alumno")
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ResetPasswordRequest{NewPassword: "newpassword"})
		request := ResetPasswordReq(string(requestBody), token)
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Expired JWT Token","status":401,"detail":"The JWT token has expired","instance":"/users/reset-password"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})
}

func TestForgotPassword(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey, RefreshTokenDuration: 300, ResetPasswordTokenDuration: 60}
	id := "1"
	t.Run("Forgot password succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return(id, nil)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ForgotPasswordRequest{Email: utils.TEST_EMAIL})
		request := ForgotPasswordReq(string(requestBody))
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Email sent successfully"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Forgot password fails due to bad request", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		invalidBody := "{}"
		request := ForgotPasswordReq(invalidBody)
		expectedStatusCode := http.StatusBadRequest
		expectedBody := `{"type":"about:blank","title":"Bad Request","status":400,"detail":"The request is missing fields","instance":"/users/forgot-password"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Forgot password fails due to internal server error email", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("", mockError)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ForgotPasswordRequest{Email: utils.TEST_EMAIL})
		request := ForgotPasswordReq(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("Forgot password returns error 404 when the given email is not registered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("", nil)
		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.ForgotPasswordRequest{Email: utils.TEST_EMAIL})
		request := ForgotPasswordReq(string(requestBody))
		expectedStatusCode := http.StatusNotFound
		expectedBody := `{"type":"about:blank","title":"The email test@email.com is not registered","status":404,"detail":"User not found","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})
}

func TestGoogleAuth(t *testing.T) {
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey, RefreshTokenDuration: 300, ResetPasswordTokenDuration: 60}
	id := "1"
	// Important: the actual token is a JWT token.
	// In this case we use an email because we are mocking the firebase service
	idToken := "john@example.com"
	studentType := "alumno"
	mockError := fmt.Errorf("mock error")
	t.Run("google authentication succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return(id, nil)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(studentType, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := GoogleAuthRequest(string(requestBody))
		expectedStatusCode := http.StatusAccepted
		statusCode, _, err := SetupRouterAndSendRequest(userService, request)
		assert.NoError(t, err)
		assert.Equal(t, expectedStatusCode, statusCode)
	})

	t.Run("google authentication fails due to email not linked", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(false, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := GoogleAuthRequest(string(requestBody))

		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"Google email not linked to existing account","status":401,"detail":"The Google email john@example.com is not linked to any existing account","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("google authentication fails due to email not registered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := GoogleAuthRequest(string(requestBody))

		expectedStatusCode := http.StatusNotFound
		expectedBody := `{"type":"about:blank","title":"The email john@example.com is not registered","status":404,"detail":"User not found","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("google authentication fails due to internal server error on repostiory.IsEmailRegistered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := GoogleAuthRequest(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("google authentication fails due to internal server error on repostiory.IsEmailLinkedToGoogleAccount", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(false, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := GoogleAuthRequest(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("google authentication fails due to internal server error on repostiory.GetUserIdByEmail", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return(id, mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := GoogleAuthRequest(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("google authentication fails due to internal server error on repostiory.GetUserType", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return(id, nil)
		userRepositoryMock.On("GetUserType", mock.Anything).Return("", mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := GoogleAuthRequest(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("linking google account to existing account succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(false, nil)
		userRepositoryMock.On("LinkGoogleEmail", mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := LinkGoogleEmail(string(requestBody))
		expectedStatusCode := http.StatusOK
		expectedBody := `{"description":"Google email linked to account successfully"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("linking google account fails due to email not registered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := LinkGoogleEmail(string(requestBody))
		expectedStatusCode := http.StatusUnauthorized
		expectedBody := `{"type":"about:blank","title":"The email john@example.com is not registered","status":404,"detail":"User not found","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("linking google account fails due to email already linked", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(true, nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := LinkGoogleEmail(string(requestBody))
		expectedStatusCode := http.StatusConflict
		expectedBody := `{"type":"about:blank","title":"Google email is already linked to existing account","status":401,"detail":"The Google email john@example.com is already linked to an existing account","instance":""}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("linking google account to existing account fails due to error on repository.IsEmailRegistered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)
		// userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(false, nil)
		// userRepositoryMock.On("LinkGoogleEmail", mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := LinkGoogleEmail(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("linking google account to existing account fails due to error on repository.IsEmailLinkedToGoogleAccount", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(false, mockError)
		// userRepositoryMock.On("LinkGoogleEmail", mock.Anything).Return(nil)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := LinkGoogleEmail(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})

	t.Run("linking google account to existing account fails due to error on repository.LinkGoogleEmail", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(false, nil)
		userRepositoryMock.On("LinkGoogleEmail", mock.Anything).Return(mockError)

		idTokenValidator := auth.MockIdTokenValidator{}
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		requestBody, _ := json.Marshal(models.GoogleAuthRequest{IdToken: idToken})
		request := LinkGoogleEmail(string(requestBody))
		expectedStatusCode := http.StatusInternalServerError
		expectedBody := `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Internal server error","instance":"/users"}`
		SetupRouterSendRequestAndCompareResults(t, userService, request, expectedStatusCode, expectedBody)
	})
}

type Request struct {
	Method  string
	Path    string
	Body    string
	Headers []RequestHeader
}

type RequestHeader struct {
	Key   string
	Value string
}

func NewRequest(method string, path string, body string, headers ...RequestHeader) Request {
	return Request{
		Method:  method,
		Path:    path,
		Body:    body,
		Headers: headers,
	}
}

func Header(key, value string) RequestHeader {
	return RequestHeader{
		Key:   key,
		Value: value,
	}
}

func SetupRouterAndSendRequest(service *service.Service, request Request) (int, string, error) {
	handler := handlers.NewUserHandler(service)

	router, err := router.CreateUserRouter(handler)
	if err != nil {
		return 0, "", err
	}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(request.Method, request.Path, strings.NewReader(request.Body))
	for _, header := range request.Headers {
		req.Header.Set(header.Key, header.Value)
	}
	router.ServeHTTP(w, req)
	return w.Code, w.Body.String(), nil
}

func SetupRouterSendRequestAndCompareResults(t *testing.T, service *service.Service, request Request, expectedStatusCode int, expectedBody string) {
	statusCode, body, err := SetupRouterAndSendRequest(service, request)
	assert.NoError(t, err)
	assert.Equal(t, expectedStatusCode, statusCode)
	assert.Equal(t, expectedBody, body)
}

func PutUserNotificationSettingsReq(id, body, token string) Request {
	request := NewRequest(
		"PUT",
		"/users/"+id+"/notification-settings",
		string(body),
		Header("Content-Type", "application/json"),
		Header("Authorization", "Bearer "+token),
	)
	return request
}

func GetUserNotificationSettingsReq(id, body, token string) Request {
	request := NewRequest(
		"GET",
		"/users/"+id+"/notification-settings",
		string(body),
		Header("Content-Type", "application/json"),
		Header("Authorization", "Bearer "+token),
	)
	return request
}

func NotifyUserReq(id, body, token string) Request {
	request := NewRequest(
		"POST",
		"/users/"+id+"/notifications",
		string(body),
		Header("Content-Type", "application/json"),
		Header("Authorization", "Bearer "+token),
	)
	return request
}

func NotificationRequestBodyWithType(notificationType string) string {
	request := models.NotifyUserRequest{
		Title:            "title",
		Body:             "body",
		NotificationType: notificationType,
	}
	body, _ := json.Marshal(request)
	return string(body)
}

func BiometricLoginReq(id, body, token string) Request {
	request := NewRequest(
		"POST",
		"/biometric-login",
		string(body),
		Header("Content-Type", "application/json"),
		Header("Authorization", "Bearer "+token),
	)
	return request
}

func VerifyUserEmailReq(id, body, token string) Request {
	request := NewRequest(
		"POST",
		"/users/verify",
		string(body),
		Header("Content-Type", "application/json"),
		Header("Authorization", "Bearer "+token),
	)
	return request
}

func RequestNewPinReq(id, body, token string) Request {
	request := NewRequest(
		"POST",
		"/users/request-new-pin",
		string(body),
		Header("Content-Type", "application/json"),
		Header("Authorization", "Bearer "+token),
	)
	return request
}

func ResetPasswordReq(body, token string) Request {
	request := NewRequest(
		"PUT",
		"/users/reset-password",
		string(body),
		Header("Content-Type", "application/json"),
		Header("Authorization", "Bearer "+token),
	)
	return request
}

func ForgotPasswordReq(body string) Request {
	request := NewRequest(
		"POST",
		"/users/forgot-password",
		body,
		Header("Content-Type", "application/json"),
	)
	return request
}

func GoogleAuthRequest(body string) Request {
	request := NewRequest(
		"POST",
		"/auth/google",
		body,
		Header("Content-Type", "application/json"),
	)
	return request
}

func LinkGoogleEmail(body string) Request {
	request := NewRequest(
		"POST",
		"/auth/link-gmail",
		body,
		Header("Content-Type", "application/json"),
	)
	return request
}
