package router

import (
	"fmt"
	"user_service/handlers"
	"user_service/service"

	"github.com/gin-gonic/gin"
)

// CreateUserRouter creates the router exposing the endpoints
func CreateUserRouter() (*gin.Engine, error) {
	service, err := service.NewService()
	if err != nil {
		return nil, fmt.Errorf("failed to create service. Error: %s", err)
	}
	handler := handlers.NewUserHandler(service)

	router := gin.Default()
	router.POST("/users", handler.CreateUser)

	return router, nil
}
