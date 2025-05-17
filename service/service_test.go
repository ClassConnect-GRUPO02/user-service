package service_test

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
	"user_service/config"
	"user_service/mocks"
	"user_service/models"
	"user_service/repository"
	"user_service/service"
	"user_service/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

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

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.LoginUser(loginRequest)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Login fails with internal server error when UserBlockedUntil returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(true, nil)
		userRepositoryMock.On("UserBlockedUntil", mock.Anything).Return(int64(0), mockError)
		userRepositoryMock.On("UserIsActivated", mock.Anything).Return(true, nil)

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.CreateUser(user)
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Register fails with internal server error when AddUser returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("IsEmailRegistered", mock.Anything).Return(false, nil)
		userRepositoryMock.On("AddUser", mock.Anything).Return(mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		_, err = userService.GetUser("1")
		assert.Equal(t, err, models.InternalServerError())
	})

	t.Run("Get Users fails with internal server error when GetUsers returns an error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUsers").Return(nil, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
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
		userService, err := service.NewService(userRepositoryMock, &config)
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
		userService, err := service.NewService(userRepositoryMock, &config)
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
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.NoError(t, err)
		expectedUserType := string(models.Student)
		assert.Equal(t, expectedUserType, userType)
	})

	t.Run("Get user type due to user not found error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), errors.New(service.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		userType, err := userService.GetUserType(userId)
		assert.Error(t, err)
		assert.Equal(t, "", userType)
	})

	t.Run("Get user type fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserType", mock.Anything).Return(string(models.Student), mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
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
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.SetUserPushToken(userId, utils.TEST_PUSH_TOKEN)
		assert.NoError(t, err)
	})

	t.Run("Set user push token fails", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("AddUserPushToken", mock.Anything, mock.Anything).Return(mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
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
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.NoError(t, err)
		assert.Equal(t, utils.TEST_PUSH_TOKEN, pushToken)
	})

	t.Run("get user push token fails due to push token not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", sql.ErrNoRows)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		pushToken, err := userService.GetUserPushToken(userId)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.MissingExpoPushToken), err)
		assert.Equal(t, "", pushToken)
	})

	t.Run("get user push token fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetUserPushToken", mock.Anything).Return("", mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
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
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		email := "john@example.com"
		subject := "Running tests"
		body := "Sorry to bother"
		err = userService.SendEmail(email, subject, body)
		assert.NoError(t, err)
	})

	t.Run("Send email verification pin succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userService, err := service.NewService(userRepositoryMock, &config)
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
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		NewAssignment:        &pushAndEmail,
		DeadlineReminder:     &pushAndEmail,
		CourseEnrollment:     &pushAndEmail,
		FavoriteCourseUpdate: &pushAndEmail,
		TeacherFeedback:      &pushAndEmail,
	}

	t.Run("set student notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.SetStudentNotificationSettings(userId, studentNotificationSettings)
		assert.NoError(t, err)
	})

	t.Run("set student notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetStudentNotificationSettings", mock.Anything, mock.Anything).Return(errors.New(repository.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config)
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
	}

	t.Run("set teacher notification settings succeeds", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.SetTeacherNotificationSettings(userId, teacherNotificationSettings)
		assert.NoError(t, err)
	})

	t.Run("set teacher notification settings fails due to user not found", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("SetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(errors.New(repository.UserNotFoundError))
		userService, err := service.NewService(userRepositoryMock, &config)
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
	}
	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		NewAssignment:        &pushAndEmail,
		DeadlineReminder:     &pushAndEmail,
		CourseEnrollment:     &pushAndEmail,
		FavoriteCourseUpdate: &pushAndEmail,
		TeacherFeedback:      &pushAndEmail,
	}

	t.Run("get student notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything, mock.Anything).Return(&studentNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		notificationSettings, err := userService.GetStudentNotificationSettings(userId)
		assert.NoError(t, err)
		assert.Equal(t, &studentNotificationSettings, notificationSettings)
	})

	t.Run("get teacher notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(&teacherNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config)
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
	}
	studentNotificationSettings := models.StudentNotificationSettingsRequest{
		PushEnabled:          &pushEnabled,
		EmailEnabled:         &emailEnabled,
		NewAssignment:        &push,
		DeadlineReminder:     &email,
		CourseEnrollment:     &pushAndEmail,
		FavoriteCourseUpdate: &pushAndEmail,
		TeacherFeedback:      &pushAndEmail,
	}
	student := models.Student
	teacher := models.Teacher

	t.Run("get student notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything, mock.Anything).Return(&studentNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config)
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
	})

	t.Run("get student notification fails due to internal server error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetStudentNotificationSettings", mock.Anything, mock.Anything).Return(nil, mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		notificationType := models.NewAssignment
		_, _, _, err = userService.GetUserNotificationPreferences(userId, student, notificationType)
		assert.Error(t, err)
	})

	t.Run("get teacher notification settings", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(&teacherNotificationSettings, nil)
		userService, err := service.NewService(userRepositoryMock, &config)
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
		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		notificationType := models.NewAssignment
		_, _, _, err = userService.GetUserNotificationPreferences(userId, teacher, notificationType)
		assert.Error(t, err)
	})

	t.Run("get user notification preferences fails due to invalid user type", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetTeacherNotificationSettings", mock.Anything, mock.Anything).Return(nil, mockError)
		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.NoError(t, err)
	})

	t.Run("Verify user email fails due to pin not found error", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(0, false, errors.New(repository.PinNotFoundError))

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.InvalidPinError), err)
	})

	t.Run("Verify user email fails due to internal server error on repository.GetPin", func(t *testing.T) {
		userRepositoryMock := new(mocks.Repository)
		userRepositoryMock.On("GetPin", mock.Anything, mock.Anything).Return(0, false, mockError)

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
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

		userService, err := service.NewService(userRepositoryMock, &config)
		assert.NoError(t, err)

		err = userService.VerifyUserEmail(email, pin)
		assert.Error(t, err)
		assert.Equal(t, errors.New(service.InternalServerError), err)
	})
}
