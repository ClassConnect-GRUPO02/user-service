package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"user_service/models"
	"user_service/service"

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
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Could not register the user",
			"instance": "/users",
		})
		return
	}
	err := h.service.CreateUser(user)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"description": "User registered successfully",
		"email":       user.Email,
		"name":        user.Name,
	})
}

func (h *UserHandler) HandleLogin(c *gin.Context) {
	loginRequest := models.LoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		log.Print("POST /login Error: Bad request")
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Could not authenticate the user",
			"instance": "/login",
		})
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
	token, err := h.service.IssueToken(userId)
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
	if token.Id == "admin" {
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
	log.Printf("idSender = %s, id = %s", idSender, id)
	// If the id of the sender is the same as the target, then
	// the user is retrieving its own info, so we respond with
	// the full information (public and private fields)
	if idSender == id {
		log.Printf("ID sender is the same as the ID target!")
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
	_, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	editUserRequest := models.EditUserRequest{}
	idString := c.Param("id")
	if err := c.ShouldBind(&editUserRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Could not update the user info",
			"instance": "/user/" + idString,
		})
		return
	}
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": "/user/" + idString,
		})
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
	id, err := h.service.GetUserIdByEmail(email)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	token, err := h.service.IssueToken(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"exists": true,
		"token":  token,
	})
}

func (h *UserHandler) HandleAdminLogin(c *gin.Context) {
	loginRequest := models.LoginRequest{}
	if err := c.ShouldBind(&loginRequest); err != nil {
		log.Print("POST /login Error: Bad request")
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Could not authenticate the user",
			"instance": "/admin-login",
		})
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
	token, err := h.service.IssueToken("admin")
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
	if token.Id != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	if err := c.ShouldBind(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Could not register the admin",
			"instance": "/admins",
		})
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
	if token.Id != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": "/user/" + idString + "/block",
		})
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
	if token.Id != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": "/user/" + idString + "/unblock",
		})
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
	if token.Id != "admin" {
		c.JSON(http.StatusUnauthorized, models.InvalidToken())
		return
	}
	idString := c.Param("id")
	userType := c.Param("type")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": "/user/" + idString + "/type/" + userType,
		})
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
	_, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	request := models.AddPushTokenRequest{}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": "/users/" + idString + "/push-token",
		})
		return
	}

	if err := c.ShouldBind(&request); err != nil {
		log.Printf("POST /users/%s/push-token Error: Bad request", idString)
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Request is missing required fields",
			"instance": fmt.Sprintf("/users/%s/push-token", idString),
		})
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
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": c.FullPath(),
		})
		return
	}

	if err := c.ShouldBind(&request); err != nil {
		log.Printf("POST /users/%s/notifications Error: Bad request", idString)
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Request is missing required fields",
			"instance": c.FullPath(),
		})
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
			c.JSON(http.StatusNotFound, models.MissingExpoPushToken(idString, c.FullPath()))
		} else {
			c.JSON(http.StatusInternalServerError, models.InternalServerError())
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description": "Sending notification",
		"id":          idString,
		"email":       userData.Email,
	})
	pushNotifications, emailNotifications, err := h.service.GetUserNotificationSettings(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	if emailNotifications {
		err = h.service.SendEmail(userData.Email, request.Title, request.Body)
		if err != nil {
			log.Printf("Failed to send email to %s. Error: %s", userData.Email, err)
		}
	}
	if pushNotifications {
		err = h.service.SendPushNotification(pushToken, request.Title, request.Body)
		if err != nil {
			log.Printf("Failed to send notification to %s. Error: %s", pushToken, err)
		}
	}
}

func (h *UserHandler) SetUserNotificationSettings(c *gin.Context) {
	_, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	request := models.SetUserNotificationSettingsRequest{}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": c.FullPath(),
		})
		return
	}

	log.Printf("request body = %v", c.Request.Body)
	if err := c.ShouldBind(&request); err != nil {
		log.Printf("POST %s Error: %s", c.FullPath(), err)
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Request is missing required fields",
			"instance": c.FullPath(),
		})
		return
	}
	err = h.service.SetUserNotificationSettings(id, *request.PushNotifications, *request.EmailNotifications)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.Error{
				Detail:   "Could not update notification settings because user was not found",
				Status:   http.StatusNotFound,
				Instance: c.FullPath(),
				Title:    "User not found",
				Type:     "about:blank",
			})
			return
		}
		// TODO: return status code depending on the error returned by the service
		c.JSON(http.StatusInternalServerError, gin.H{
			"description": "Failed to update user notification settings",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"description":        "User notification settings updated successfully",
		"id":                 idString,
		"pushNotifications":  request.PushNotifications,
		"emailNotifications": request.EmailNotifications,
	})
}

func (h *UserHandler) GetUserNotificationSettings(c *gin.Context) {
	_, err := h.ValidateToken(c)
	if err != nil {
		return
	}
	idString := c.Param("id")
	id, err := strconv.ParseInt(idString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Invalid id: " + idString,
			"instance": c.FullPath(),
		})
		return
	}
	pushNotifications, emailNotifications, err := h.service.GetUserNotificationSettings(id)
	if err != nil {
		if err.Error() == service.UserNotFoundError {
			c.JSON(http.StatusNotFound, models.Error{
				Detail:   "User not found",
				Status:   http.StatusNotFound,
				Instance: c.FullPath(),
				Title:    "User not found",
				Type:     "about:blank",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, models.InternalServerError())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"pushNotifications":  pushNotifications,
		"emailNotifications": emailNotifications,
	})
}
