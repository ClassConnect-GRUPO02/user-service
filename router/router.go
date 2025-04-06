package router

import (
	"user_service/handlers"
	"user_service/service"

	"github.com/gin-gonic/gin"
)

// CreateUserRouter creates the router exposing the endpoints
func CreateUserRouter() *gin.Engine {
	service := service.NewService()
	handler := handlers.NewUserHandler(service)

	router := gin.Default()
	router.POST("/users", handler.CreateUser)

	return router
}
