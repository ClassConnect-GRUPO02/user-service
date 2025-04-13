package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strings"
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

	token, err := h.service.LoginUser(loginRequest)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"description": "User logged in successfully",
		"token":       token,
	})
}

func (h *UserHandler) GetUsers(c *gin.Context) {
	err := h.ValidateToken(c)
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
	err := h.ValidateToken(c)
	if err != nil {
		return
	}
	id, isPresent := c.Params.Get("id")
	if !isPresent {
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Missing id",
			"instance": "/user",
		})
		return
	}
	user, err := h.service.GetUser(id)
	if err, ok := err.(*models.Error); ok {
		c.JSON(err.Status, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

func extractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("missing JWT token")
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", fmt.Errorf("expected Bearer authorization header")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	return token, nil
}
