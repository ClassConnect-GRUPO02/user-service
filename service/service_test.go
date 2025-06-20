package service_test

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"
	"user_service/auth"
	"user_service/config"
	"user_service/mocks"
	"user_service/models"
	"user_service/repository"
	"user_service/service"
	"user_service/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const SECRET_KEY = "f1d401c836ec1d97ac4ad9bae38a8963ffc9c495627eff4160102874a5290428bd5ae1d5b6dce8f065e91502e9e722cdd4170c4fb6e3339cd63d9b6bc905c9953c0a8ace2195bb0048c8441a1f9da20b64f222bb9f539acd997d2675bf7bb93f11750abf2a7be29b9d066c064c85f309a5b6735efe3c7d36c6d0c6972f9431a19ec423ea7d6a2991679d33eb0db4992ed0641df243c94bc808a08d1e820bd5a70636fd4aa8a6a4c23f7b32d096e77f81a5ffaf4d9eac6da578326324d62ec5ff418fe5a28adc3751a5fecfb4ecab7ec77ca49e3a6978a56aa557912891291d4f20c2eae0236b074402fb116831dd8a0464ab1510415493b8951d98db4365afac"

func TestServiceLoginWithRepositoryErrors(t *testing.T) {
	loginRequest := models.LoginRequest{
		Email:    "john@example.com",
		Password: "password",
	}
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	t.Run("Login fails with internal server error when IsEmailRegistered returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when UserBlockedUntil returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), mockError)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when PasswordMatches returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, mockError)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when IncrementFailedLoginAttempts returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)
		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(0), mockError)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when SetUserBlockedUntil returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), nil)
		userRepositoryMock.On("PasswordMatches", mock.Anything, mock.Anything).Return(false, nil)
		userRepositoryMock.On("IncrementFailedLoginAttempts", mock.Anything, mock.Anything).Return(int64(1), nil)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("1", nil)
		userRepositoryMock.On("SetUserBlockedUntil", mock.Anything, mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})
}

func TestServiceRegisterWithRepositoryErrors(t *testing.T) {
	user := models.User{}
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	t.Run("Register fails with internal server error when IsEmailRegistered returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Register fails with internal server error when AddUser returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddUser", mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		assert.Equal(t, err, models.InternalServerError())
	})
}

func TestServiceGetUserWithRepositoryErrors(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	t.Run("Get User fails with internal server error when GetUser returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUser", mock.Anything).Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		_, err = userService.GetUser("1")
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Get Users fails with internal server error when GetUsers returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		_, err = userService.GetUsers()
		assert.Equal(t, err, models.InternalServerError())
	})
}

func TestServiceEditUserWithRepositoryErrors(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}

	t.Run("Edit user fails with internal server error when repository.UpdateUser returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(mockError)

		editUserRequest := models.EditUserRequest{Name: "Johnny", Email: "johnny@example.com"}
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.EditUser(1, editUserRequest)
		expectedError := models.InternalServerError()
		assert.Equal(t, expectedError, err)
	})
}

func TestServiceIsEmailRegisteredWithRepositoryErrors(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}

	t.Run("IsEmailRegistered returns internal server error when repository.IsEmailRegistered returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, mockError)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		_, err = userService.IsEmailRegistered("john@example.com")
		expectedError := models.InternalServerError()
		assert.Equal(t, expectedError, err)
	})
}

func TestServiceGetUserType(t *testing.T) {
	mockError := fmt.Errorf("mock error")
	config := config.Config{}
	userId := int64(1)
	t.Run("Get user type succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.NoError(t, err)
		expectedUserType := string(models.Student)
		assert.Equal(t, expectedUserType, userType)
	})

	t.Run("Get user type due to user not found error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), errors.New(service.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.Error(t, err)
		assert.Equal(t, "", userType)
	})

	t.Run("Get user type fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), mockError)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.Error(t, err)
		assert.Equal(t, "", userType)
	})
}

func TestServiceSetUserPushToken(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	mockError := fmt.Errorf("mock error")
	t.Run("Set user push token succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.SetUserPushToken(userId, utils.TEST_PUSH_TOKEN)
		assert.NoError(t, err)
	})

	t.Run("Set user push token fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(mockError)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.SetUserPushToken(userId, utils.TEST_PUSH_TOKEN)
		assert.Error(t, err)
	})
}

func TestServiceGetUserPushToken(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	mockError := fmt.Errorf("mock error")
	t.Run("Get user push token succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return(utils.TEST_PUSH_TOKEN, nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.NoError(t, err)
		assert.Equal(t, utils.TEST_PUSH_TOKEN, pushToken)
	})

	t.Run("get user push token fails due to push token not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", sql.ErrNoRows)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.MissingExpoPushToken), err)
		assert.Equal(t, "", pushToken)
	})

	t.Run("get user push token fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", mockError)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.Error(t, err)
		assert.Equal(t, "", pushToken)
	})
}

func TestServiceSendEmail(t *testing.T) {
	emailPassword, err := utils.GetEnvVar("EMAIL_PASSWORD")
	assert.NoError(t, err)
	config := config.Config{
		Email:         "classconnect42@gmail.com",
		EmailPassword: emailPassword,
	}
	t.Run("Send email succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		email := "john@example.com"
		subject := "Running tests"
		body := "Sorry to bother"
		err = userService.SendEmail(email, subject, body)
		assert.NoError(t, err)
	})

	t.Run("Send email verification pin succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		email := "john@example.com"
		pin := 999999
		err = userService.SendEmailVerificationPin(email, pin)
		assert.NoError(t, err)
	})
}

func TestServiceSetStudentNotificationSettings(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
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

	t.Run("set student notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.SetStudentNotificationSettings(userId, studentNotificationSettings)
		assert.NoError(t, err)
	})

	t.Run("set student notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(errors.New(repository.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.SetStudentNotificationSettings(userId, studentNotificationSettings)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.UserNotFoundError), err)
	})
}

func TestServiceSetTeacherNotificationSettings(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	pushEnabled := true
	emailEnabled := true
	pushAndEmail := models.PushAndEmail
	teacherNotificationSettings := models.TeacherNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		AssignmentSubmission: &pushAndEmail,
		StudentFeedback:      &pushAndEmail,
		CourseAssigned:       &pushAndEmail,
		CourseRevoked:        &pushAndEmail,
	}

	t.Run("set teacher notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.SetTeacherNotificationSettings(userId, teacherNotificationSettings)
		assert.NoError(t, err)
	})

	t.Run("set teacher notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(errors.New(repository.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.SetTeacherNotificationSettings(userId, teacherNotificationSettings)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.UserNotFoundError), err)
	})
}

func TestServiceGetUserNotificationSettings(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	pushEnabled := true
	emailEnabled := true
	pushAndEmail := models.PushAndEmail
	teacherNotificationSettings := models.TeacherNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		AssignmentSubmission: &pushAndEmail,
		StudentFeedback:      &pushAndEmail,
		CourseAssigned:       &pushAndEmail,
		CourseRevoked:        &pushAndEmail,
	}
	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:      &pushEnabled,
		EmailEnabled:     &emailEnabled,
		NewAssignment:    &pushAndEmail,
		DeadlineReminder: &pushAndEmail,
		CourseEnrollment: &pushAndEmail,
		TeacherFeedback:  &pushAndEmail,
		GradingAvailable: &pushAndEmail,
	}

	t.Run("get student notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything, mock.Anything).Return(&studentNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		notificationSettings, err := userService.GetStudentNotificationSettings(userId)
		assert.NoError(t, err)
		assert.Equal(t, &studentNotificationSettings, notificationSettings)
	})

	t.Run("get teacher notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(&teacherNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		notificationSettings, err := userService.GetTeacherNotificationSettings(userId)
		assert.NoError(t, err)
		assert.Equal(t, &teacherNotificationSettings, notificationSettings)
	})
}

func TestServiceGetUserNotificationPreferences(t *testing.T) {
	config := config.Config{}
	userId := int64(1)
	mockError := fmt.Errorf("mock error")
	pushEnabled := true
	emailEnabled := true
	pushAndEmail := models.PushAndEmail
	push := models.Push
	email := models.Email
	teacherNotificationSettings := models.TeacherNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		AssignmentSubmission: &push,
		StudentFeedback:      &email,
		CourseAssigned:       &pushAndEmail,
		CourseRevoked:        &pushAndEmail,
	}
	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:      &pushEnabled,
		EmailEnabled:     &emailEnabled,
		NewAssignment:    &push,
		DeadlineReminder: &email,
		CourseEnrollment: &pushAndEmail,
		TeacherFeedback:  &pushAndEmail,
		GradingAvailable: &pushAndEmail,
	}
	student := models.Student
	teacher := models.Teacher

	t.Run("get student notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything, mock.Anything).Return(&studentNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		notificationType := models.NewAssignment
		pushEnabled, emailEnabled, notificationPreference, err := userService.GetUserNotificationPreferences(userId, student, notificationType)
		assert.NoError(t, err)
		assert.Equal(t, true, pushEnabled)
		assert.Equal(t, true, emailEnabled)
		assert.Equal(t, models.Push, notificationPreference)

		notificationType = models.DeadlineReminder
		pushEnabled, emailEnabled, notificationPreference, err = userService.GetUserNotificationPreferences(userId, student, notificationType)
		assert.NoError(t, err)
		assert.Equal(t, true, pushEnabled)
		assert.Equal(t, true, emailEnabled)
		assert.Equal(t, models.Email, notificationPreference)

		notificationType = models.CourseEnrollment
		pushEnabled, emailEnabled, notificationPreference, err = userService.GetUserNotificationPreferences(userId, student, notificationType)
		assert.NoError(t, err)
		assert.Equal(t, true, pushEnabled)
		assert.Equal(t, true, emailEnabled)
		assert.Equal(t, models.PushAndEmail, notificationPreference)

		notificationType = models.GradingAvailable
		pushEnabled, emailEnabled, notificationPreference, err = userService.GetUserNotificationPreferences(userId, student, notificationType)
		assert.NoError(t, err)
		assert.Equal(t, true, pushEnabled)
		assert.Equal(t, true, emailEnabled)
		assert.Equal(t, models.PushAndEmail, notificationPreference)
	})

	t.Run("get student notification fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything, mock.Anything).Return(nil, mockError)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		notificationType := models.NewAssignment
		_, _, _, err = userService.GetUserNotificationPreferences(userId, student, notificationType)
		assert.Error(t, err)
	})

	t.Run("get teacher notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(&teacherNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		notificationType := models.AssignmentSubmission
		pushEnabled, emailEnabled, notificationPreference, err := userService.GetUserNotificationPreferences(userId, teacher, notificationType)
		assert.NoError(t, err)
		assert.Equal(t, true, pushEnabled)
		assert.Equal(t, true, emailEnabled)
		assert.Equal(t, models.Push, notificationPreference)

		notificationType = models.StudentFeedback
		pushEnabled, emailEnabled, notificationPreference, err = userService.GetUserNotificationPreferences(userId, teacher, notificationType)
		assert.NoError(t, err)
		assert.Equal(t, true, pushEnabled)
		assert.Equal(t, true, emailEnabled)
		assert.Equal(t, models.Email, notificationPreference)
	})

	t.Run("get teacher notification fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(nil, mockError)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		notificationType := models.NewAssignment
		_, _, _, err = userService.GetUserNotificationPreferences(userId, teacher, notificationType)
		assert.Error(t, err)
	})

	t.Run("get user notification preferences fails due to invalid user type", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(nil, mockError)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		notificationType := models.NewAssignment
		invalidUserType := "abc"
		_, _, _, err = userService.GetUserNotificationPreferences(userId, models.UserType(invalidUserType), notificationType)
		assert.Error(t, err)
	})
}

func TestServiceVerifyUserEmail(t *testing.T) {
	config := config.Config{}
	// userId := int64(1)
	mockError := fmt.Errorf("mock error")
	email := "john@example.com"
	pin := 999999

	t.Run("Verify user email suceeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := int(time.Now().Unix() + 300)
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)
		userRepositoryMock.On("SetPinAsConsumed", mock.Anything, mock.Anything).Return(nil)
		userRepositoryMock.On("ActivateUserEmail", mock.Anything).Return(nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.NoError(t, err)
	})

	t.Run("Verify user email fails due to pin not found error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(0, false, errors.New(repository.PinNotFoundError))

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.InvalidPinError), err)
	})

	t.Run("Verify user email fails due to internal server error on repository.GetPin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(0, false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.InternalServerError), err)
	})

	t.Run("Verify user email fails due to invalid pin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := 0
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.InvalidPinError), err)
	})

	t.Run("Verify user email fails due to expired pin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := int(time.Now().Unix() - 300)
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.ExpiredPinError), err)
	})

	t.Run("Verify user email fails due to internal server error on repository.SetPinAsConsumed", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := int(time.Now().Unix() + 300)
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)
		userRepositoryMock.On("SetPinAsConsumed", mock.Anything, mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.InternalServerError), err)
	})

	t.Run("Verify user email fails due to internal server error on repository.ActivateUserEmail", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		expirationTimestamp := int(time.Now().Unix() + 300)
		consumed := false
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(expirationTimestamp, consumed, nil)
		userRepositoryMock.On("SetPinAsConsumed", mock.Anything, mock.Anything).Return(nil)
		userRepositoryMock.On("ActivateUserEmail", mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.InternalServerError), err)
	})
}

func TestServiceIssueToken(t *testing.T) {
	secretKey, err := hex.DecodeString(SECRET_KEY)
	assert.NoError(t, err)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}

	userRepositoryMock := new(mocks.Repository)
	userService, err := service.NewService(userRepositoryMock, &config, nil)
	assert.NoError(t, err)
	t.Run("Issue token includes user type", func(t *testing.T) {
		id := "1"
		userType := "alumno"
		token, err := userService.IssueToken(id, userType)
		assert.NoError(t, err)
		tokenClaims, err := userService.ValidateToken(token)
		assert.NoError(t, err)
		assert.Equal(t, userType, tokenClaims.UserType)
	})
}

func TestServiceUserIsBlocked(t *testing.T) {
	config := config.Config{BlockingDuration: 300}

	t.Run("Service.UserIsBlocked returns false when blockedUntil is 0", func(t *testing.T) {
		blockedUntil := int64(0)
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(blockedUntil, nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		userIsBlocked, err := userService.UserIsBlocked(utils.TEST_EMAIL)
		assert.NoError(t, err)
		assert.False(t, userIsBlocked)
	})

	t.Run("Service.UserIsBlocked returns true when blockedUntil is greater than timestamp no", func(t *testing.T) {
		blockedUntil := int64(time.Now().Unix() + 300)
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(blockedUntil, nil)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		userIsBlocked, err := userService.UserIsBlocked(utils.TEST_EMAIL)
		assert.NoError(t, err)
		assert.True(t, userIsBlocked)
	})

	t.Run("Service.UserIsBlocked returns internal server error when repository.UserBlockedUntil returns error", func(t *testing.T) {
		blockedUntil := int64(0)
		mockError := fmt.Errorf("mock error")
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(blockedUntil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)

		_, err = userService.UserIsBlocked(utils.TEST_EMAIL)
		assert.Error(t, err)
	})
}

func TestServiceGetUserIdByEmail(t *testing.T) {
	secretKey, err := hex.DecodeString(SECRET_KEY)
	assert.NoError(t, err)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}

	t.Run("Get user id by email returns error when the email is not registered", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserIdByEmail", mock.Anything).Return("", nil)
		userService, err := service.NewService(userRepositoryMock, &config, nil)
		assert.NoError(t, err)
		email := "john@example.com"
		userId, err := userService.GetUserIdByEmail(email)
		assert.Equal(t, "", userId)
		assert.Error(t, err)
		expectedError := models.EmailNotFoundError(email)
		assert.Equal(t, expectedError, err)
	})
}

func TestServiceGoogleAuthentication(t *testing.T) {
	secretKey, err := hex.DecodeString(SECRET_KEY)
	assert.NoError(t, err)
	config := config.Config{TokenDuration: 300, SecretKey: secretKey}
	idTokenValidator := auth.MockIdTokenValidator{}
	idToken := utils.TEST_EMAIL
	email := utils.TEST_EMAIL
	mockError := fmt.Errorf("mock error")
	t.Run("firebase id token verification succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		_, err = userService.ValidateIdTokenAndGetEmail(idToken)
		assert.NoError(t, err)
	})

	t.Run("google account linking succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("LinkGoogleEmail", mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		err = userService.LinkGoogleEmail(email)
		assert.NoError(t, err)
	})

	t.Run("google account linking returns error when the database query fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("LinkGoogleEmail", mock.Anything).Return(mockError)
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		err = userService.LinkGoogleEmail(email)
		assert.Error(t, err)
	})

	t.Run("IsEmailLinkedToGoogleAccount works as expected", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(true, nil)
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		isEmailLinked, err := userService.IsEmailLinkedToGoogleAccount(email)
		assert.NoError(t, err)
		assert.True(t, isEmailLinked)
	})

	t.Run("IsEmailLinkedToGoogleAccount returns error when the database query fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailLinkedToGoogleAccount", mock.Anything).Return(false, mockError)
		userService, err := service.NewService(userRepositoryMock, &config, &idTokenValidator)
		assert.NoError(t, err)
		_, err = userService.IsEmailLinkedToGoogleAccount(email)
		assert.Error(t, err)
	})
}
