package handlers

import (
	"log"
	"net/http"
	"user_service/models"
	"user_service/service"

	"github.com/gin-gonic/gin"
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
	_, err := h.ValidateToken(c)
	if err != nil {
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
	idSender, err := h.service.GetUserIdFromToken(token)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
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
