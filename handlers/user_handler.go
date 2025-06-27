package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"user_service/models"
	"user_service/service"
	"user_service/utils"

	"github.com/gin-gonic/gin"
	expo "github.com/oliveroneill/exponent-server-sdk-golang/sdk"
)

type UserHandler struct {
	service *service.Service
}

func NewUserHandler(service *service.Service) *UserHandler {
	handler := UserHandler{
		service: service,
	}
	return &handler
}

func (h *UserHandler) CreateUser(c *gin.Context) {
	user := models.User{}
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	err := h.service.CreateUser(user)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	pin, err := h.service.IssueVerificationPinForEmail(user.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	err = h.service.SendEmailVerificationPin(user.Email, pin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.InternalServerError())
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"description": "Verification PIN sent to the provided email",
		"email":       user.Email,
		"name":        user.Name,
		"duration":    h.service.VerificationPinDurationInMinutes(),
	})
}

func (h *UserHandler) VerifyUserEmail(c *gin.Context) {
	request := models.EmailVerificationRequest{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	err := h.service.VerifyUserEmail(request.Email, request.Pin)
	if err != nil {
		switch err.Error() {
		case service.InvalidPinError:
			c.JSON(http.StatusUnauthorized, models.InvalidPinError(request.Pin, c.Request.URL.Path))
		case service.ConsumedPinError:
			c.JSON(http.StatusUnauthorized, models.InvalidPinError(request.Pin, c.Request.URL.Path))
		case service.ExpiredPinError:
			c.JSON(http.StatusUnauthorized, models.ExpiredPinError(request.Pin, c.Request.URL.Path))
		case service.InternalServerError:
			c.JSON(http.StatusUnauthorized, models.InternalServerError())
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "Email verified successfully",
		"email":       request.Email,
	})
}

func (h *UserHandler) RequestNewPin(c *gin.Context) {
	request := models.RequestNewVerificationPin{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	pin, err := h.service.IssueVerificationPinForEmail(request.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	err = h.service.SendEmailVerificationPin(request.Email, pin)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "Verification PIN sent to email",
		"email":       request.Email,
	})
}

func (h *UserHandler) HandleLogin(c *gin.Context) {
	loginRequest := models.LoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		log.Print("POST /login Error: Bad request")
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	err := h.service.LoginUser(loginRequest)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	userId, err := h.service.GetUserIdByEmail(loginRequest.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	id, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(userId, c.Request.URL.Path))
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(userId))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	refreshToken, err := h.service.IssueRefreshToken(userId)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description":  "User logged in successfully",
		"id":           userId,
		"token":        token,
		"refreshToken": refreshToken,
	})
}

func (h *UserHandler) HandleBiometricLogin(c *gin.Context) {
	loginRequest := models.BiometricLoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		log.Printf("%s Error: %s", c.Request.URL.Path, err)
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	refreshToken, err := h.service.ValidateRefreshToken(loginRequest.RefreshToken)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	userId := refreshToken.Id
	user, err := h.service.GetUser(userId)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	userIsBlocked, err := h.service.UserIsBlocked(user.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if userIsBlocked {
		c.JSON(http.StatusForbidden, models.UserBlockedError())
		return
	}

	userType := user.UserType
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description": "User logged in successfully",
		"id":          userId,
		"token":       token,
	})
}

func (h *UserHandler) GetUsers(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	// If the sender is the admin, then return the full user info,
	// which contains information such as registration date, whether the user
	// is blocked, etc.
	if token.UserType == "admin" {
		users, err := h.service.GetUsersFullInfo()
		if err, ok := err.(*models.Error); ok {
			c.JSON(err.Status, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"users": users,
		})
		return
	}
	users, err := h.service.GetUsers()
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

func (h *UserHandler) GetUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	id := c.Param("id")
	// Retrieve the user by its id
	user, err := h.service.GetUser(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	// Get the ID of the sender from the JWT token
	idSender := token.Id

	// If the id of the sender is the same as the target, then
	// the user is retrieving its own info, so we respond with
	// the full information (public and private fields)
	if idSender == id {
		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
		return
	}
	// Otherwise, respond only with the public fields
	// (omit the private ones like the location)
	c.JSON(http.StatusOK, gin.H{
		"user": models.UserPublicInfo{
			Id:       user.Id,
			Name:     user.Name,
			Email:    user.Email,
			UserType: user.UserType,
		},
	})
}

func (h *UserHandler) EditUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	editUserRequest := models.EditUserRequest{}
	idString := c.Param("id")
	if err := c.ShouldBind(&editUserRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	// Check the sender of the request is the actual user
	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	err = h.service.EditUser(id, editUserRequest)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User updated successfully",
	})
}

func (h *UserHandler) ResetPassword(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if h.service.ResetPasswordTokenHasExpired(token.IssuedAt) {
		c.JSON(http.StatusUnauthorized, models.ExpiredTokenError(c.Request.URL.Path))
		return
	}
	resetPasswordRequest := models.ResetPasswordRequest{}
	if err := c.ShouldBind(&resetPasswordRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	id, err := strconv.ParseInt(token.Id, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(token.Id, c.Request.URL.Path))
		return
	}

	err = h.service.ResetPassword(id, resetPasswordRequest.NewPassword)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "Password reset successfully",
	})
}

func (h *UserHandler) ForgotPassword(c *gin.Context) {
	forgotPasswordRequest := models.ForgotPasswordRequest{}
	if err := c.ShouldBind(&forgotPasswordRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	email := forgotPasswordRequest.Email
	userId, err := h.service.GetUserIdByEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	token, err := h.service.IssueToken(userId, "")
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	resetPasswordUrl := fmt.Sprintf("https://classconnect-reset.netlify.app/?token=%s", token)
	tokenDuration := h.service.ResetPasswordTokenDurationInMinutes()
	emailSubject := "ClassConnect - Recuperación de contraseña"
	emailBody := utils.GetResetPasswordMessage(email, resetPasswordUrl, tokenDuration)
	err = h.service.SendEmail(email, emailSubject, emailBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.InternalServerError())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "Email sent successfully",
	})
}

func (h *UserHandler) EmailExists(c *gin.Context) {
	email := c.Param("email")
	emailExists, err := h.service.IsEmailRegistered(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if !emailExists {
		c.JSON(http.StatusOK, gin.H{
			"exists": false,
		})
		return
	}
	userId, err := h.service.GetUserIdByEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	id, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(userId, c.Request.URL.Path))
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(userId))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"exists": true,
		"token":  token,
		"id":     id,
	})
}

func (h *UserHandler) HandleAdminLogin(c *gin.Context) {
	loginRequest := models.LoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	err := h.service.LoginAdmin(loginRequest)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	adminId, err := h.service.GetAdminIdByEmail(loginRequest.Email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	token, err := h.service.IssueToken(adminId, "admin")
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description": "Admin logged in successfully",
		"id":          adminId,
		"token":       token,
	})
}

func (h *UserHandler) CreateAdmin(c *gin.Context) {
	admin := models.CreateAdminRequest{}
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	if err := c.ShouldBind(&admin); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	err = h.service.CreateAdmin(admin)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"description": "Admin registered successfully",
		"email":       admin.Email,
		"name":        admin.Name,
	})
}

func (h *UserHandler) BlockUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	err = h.service.BlockUser(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User blocked successfully",
		"id":          idString,
		"blocked":     true,
	})
}

func (h *UserHandler) UnblockUser(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	err = h.service.UnblockUser(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User unblocked successfully",
		"id":          idString,
		"blocked":     false,
	})
}

func (h *UserHandler) SetUserType(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	if token.UserType != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	userType := c.Param("type")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	err = h.service.SetUserType(id, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "User type updated successfully",
		"id":          idString,
		"userType":    userType,
	})
}

func (h *UserHandler) AddPushToken(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	request := models.AddPushTokenRequest{}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}

	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}

	if err := c.ShouldBind(&request); err != nil {
		log.Printf("POST /users/%s/push-token Error: Bad request", idString)
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}

	_, err = expo.NewExponentPushToken(request.PushToken)
	if err != nil {
		err = models.InvalidExpoToken(id, request.PushToken)
		c.JSON(http.StatusUnauthorized, err)
		return
	}

	err = h.service.SetUserPushToken(id, request.PushToken)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"description": "User push token set successfully",
		"id":          idString,
		"token":       request.PushToken,
	})
}

func (h *UserHandler) NotifyUser(c *gin.Context) {
	request := models.NotifyUserRequest{}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}

	if err := c.ShouldBind(&request); err != nil {
		log.Printf("POST /users/%s/notifications Error: Bad request", idString)
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	userData, err := h.service.GetUser(idString)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	pushToken, err := h.service.GetUserPushToken(id)
	if err != nil {
		if err.Error() == service.MissingExpoPushToken {
			c.JSON(http.StatusNotFound, models.MissingExpoPushToken(idString, c.Request.URL.Path))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}

	notificationType := request.NotificationType
	userType := models.UserType(strings.ToLower(userData.UserType))

	pushEnabled, emailEnabled, notificationPreference, err := h.service.GetUserNotificationPreferences(id, userType, notificationType)
	if err != nil {
		switch err.Error() {
		case service.InternalServerError:
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		case service.InvalidNotificationType:
			c.JSON(http.StatusBadRequest, models.BadRequestInvalidNotificationType(notificationType, c.Request.URL.Path))
		case service.InvalidUserType:
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	sendPushNotification := false
	sendEmailNotification := false

	switch notificationPreference {
	case models.Push:
		sendPushNotification = true
	case models.Email:
		sendEmailNotification = true
	case models.PushAndEmail:
		sendPushNotification = true
		sendEmailNotification = true
	}

	if sendEmailNotification && emailEnabled {
		err = h.service.SendEmail(userData.Email, request.Title, request.Body)
		if err != nil {
			log.Printf("Failed to send email to %s. Error: %s", userData.Email, err)
		}
	}
	if sendPushNotification && pushEnabled {
		err = h.service.SendPushNotification(pushToken, request.Title, request.Body)
		if err != nil {
			log.Printf("Failed to send notification to %s. Error: %s", pushToken, err)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "Notification scheduled",
		"id":          idString,
		"email":       userData.Email,
	})
}

func (h *UserHandler) SetUserNotificationSettings(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}

	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	if models.UserType(userType) == models.Student {
		notificationSettings := models.StudentNotificationSettingsRequest{}
		if err := c.ShouldBind(&notificationSettings); err != nil {
			log.Printf("POST %s Error: %s", c.Request.URL.Path, err)
			c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
			return
		}
		err := h.service.SetStudentNotificationSettings(id, notificationSettings)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
			return
		}
	} else if models.UserType(userType) == models.Teacher {
		notificationSettings := models.TeacherNotificationSettingsRequest{}
		if err := c.ShouldBind(&notificationSettings); err != nil {
			log.Printf("POST %s Error: %s", c.Request.URL.Path, err)
			c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
			return
		}
		err := h.service.SetTeacherNotificationSettings(id, notificationSettings)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "Notification settings updated successfully",
		"id":          id,
	})
}

func (h *UserHandler) GetUserNotificationSettings(c *gin.Context) {
	token, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(idString, c.Request.URL.Path))
		return
	}
	if token.Id != idString {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	if models.UserType(userType) == models.Student {
		notificationSettings, err := h.service.GetStudentNotificationSettings(id)
		if err != nil {
			if err.Error() == service.UserNotFoundError {
				c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
			} else {
				c.JSON(http.StatusInternalServerError, models.InternalServerError())
			}
			return
		}
		c.JSON(http.StatusOK, notificationSettings)
	} else if models.UserType(userType) == models.Teacher {
		notificationSettings, err := h.service.GetTeacherNotificationSettings(id)
		if err != nil {
			if err.Error() == service.UserNotFoundError {
				c.JSON(http.StatusNotFound, models.UserNotFoundError(idString))
			} else {
				c.JSON(http.StatusInternalServerError, models.InternalServerError())
			}
			return
		}
		c.JSON(http.StatusOK, notificationSettings)
	}
}

func (h *UserHandler) HandleGoogleAuth(c *gin.Context) {
	request := models.GoogleAuthRequest{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	email, err := h.service.ValidateIdTokenAndGetEmail(request.IdToken)
	if err != nil {
		log.Printf("failed to verify Google id token. Error: %s", err)
		c.JSON(http.StatusBadRequest, models.FailedToVerifyFirebaseToken(c.Request.URL.Path, err.Error()))
		return
	}
	isEmailRegistered, err := h.service.IsEmailRegistered(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if !isEmailRegistered {
		c.JSON(http.StatusNotFound, models.EmailNotFoundError(email))
		return
	}
	isEmailLinkedToGoogleAccount, err := h.service.IsEmailLinkedToGoogleAccount(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	if !isEmailLinkedToGoogleAccount {
		c.JSON(http.StatusUnauthorized, models.GoogleEmailNotLinked(email))
		return
	}
	userIsBlocked, err := h.service.UserIsBlocked(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if userIsBlocked {
		c.JSON(http.StatusForbidden, models.UserBlockedError())
		return
	}
	userId, err := h.service.GetUserIdByEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	id, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestInvalidId(userId, c.Request.URL.Path))
		return
	}
	userType, err := h.service.GetUserType(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.UserNotFoundError(userId))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	token, err := h.service.IssueToken(userId, userType)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	refreshToken, err := h.service.IssueRefreshToken(userId)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"description":  "User logged in successfully",
		"id":           userId,
		"token":        token,
		"refreshToken": refreshToken,
	})
}

func (h *UserHandler) LinkGoogleEmail(c *gin.Context) {
	request := models.GoogleAuthRequest{}
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, models.BadRequestMissingFields(c.Request.URL.Path))
		return
	}
	email, err := h.service.ValidateIdTokenAndGetEmail(request.IdToken)
	if err != nil {
		log.Printf("failed to verify Firebase id token. Error: %s", err)
		c.JSON(http.StatusBadRequest, models.FailedToVerifyFirebaseToken(c.Request.URL.Path, err.Error()))
		return
	}
	isEmailRegistered, err := h.service.IsEmailRegistered(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if !isEmailRegistered {
		c.JSON(http.StatusUnauthorized, models.EmailNotFoundError(email))
		return
	}
	isEmailLinkedToGoogleAccount, err := h.service.IsEmailLinkedToGoogleAccount(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	if isEmailLinkedToGoogleAccount {
		c.JSON(http.StatusConflict, models.GoogleEmailAlreadyLinked(email))
		return
	}

	err = h.service.LinkGoogleEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"description": "Google email linked to account successfully"})
}
