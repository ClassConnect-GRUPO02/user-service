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
	log.Print("Received a POST /users request!")
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
