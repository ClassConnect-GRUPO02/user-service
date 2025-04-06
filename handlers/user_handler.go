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
		log.Print("Error: Bad request")
		c.JSON(http.StatusBadRequest, gin.H{
			// TODO: handle error
		})
		return
	}
	// TODO: check errors
	h.service.CreateUser(user)

	c.JSON(http.StatusCreated, nil)
}
