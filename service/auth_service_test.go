package service_test

import (
	"encoding/hex"
	"testing"
	"user_service/auth"
	"user_service/config"
	"user_service/mocks"
	"user_service/models"
	"user_service/service"

	"github.com/stretchr/testify/assert"
)

const TEST_SECRET_KEY = "f1d401c836ec1d97ac4ad9bae38a8963ffc9c495627eff4160102874a5290428bd5ae1d5b6dce8f065e91502e9e722cdd4170c4fb6e3339cd63d9b6bc905c9953c0a8ace2195bb0048c8441a1f9da20b64f222bb9f539acd997d2675bf7bb93f11750abf2a7be29b9d066c064c85f309a5b6735efe3c7d36c6d0c6972f9431a19ec423ea7d6a2991679d33eb0db4992ed0641df243c94bc808a08d1e820bd5a70636fd4aa8a6a4c23f7b32d096e77f81a5ffaf4d9eac6da578326324d62ec5ff418fe5a28adc3751a5fecfb4ecab7ec77ca49e3a6978a56aa557912891291d4f20c2eae0236b074402fb116831dd8a0464ab1510415493b8951d98db4365afac"

func TestTokenValidation(t *testing.T) {
	userRepositoryMock := new(mocks.Repository)
	secretKey, _ := hex.DecodeString(TEST_SECRET_KEY)
	auth := auth.Auth{SecretKey: secretKey}
	id := "1"
	userType := "alumno"
	token, _ := auth.IssueToken(id, userType)

	t.Run("validate valid token", func(t *testing.T) {
		config := config.Config{SecretKey: secretKey, TokenDuration: 300}
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		_, err = userService.ValidateToken(token)
		assert.NoError(t, err)
	})

	t.Run("validate expired token returns an error", func(t *testing.T) {
		// Set token duration to 0
		config := config.Config{SecretKey: secretKey, TokenDuration: 0}
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		_, err = userService.ValidateToken(token)
		// The error should be session expired
		expectedError := models.SessionExpired()
		assert.Equal(t, expectedError, err)
	})

	t.Run("validate invalid token returns an error", func(t *testing.T) {
		config := config.Config{SecretKey: secretKey, TokenDuration: 300}
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)
		invalidToken := "invalid token"
		_, err = userService.ValidateToken(invalidToken)
		expectedError := models.InvalidToken()
		assert.Equal(t, expectedError, err)
	})
}
