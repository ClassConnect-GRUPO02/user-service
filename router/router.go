package router

import (
	"fmt"
	"user_service/handlers"
	"user_service/repository"
	"user_service/service"

	"github.com/gin-gonic/gin"
)

// CreateUserRouter creates the router exposing the endpoints
func CreateUserRouter() (*gin.Engine, error) {
	repository, err := repository.NewUserRepository()
	if err != nil {
		return nil, fmt.Errorf("failed to create user repository. Error: %s", err)
	}

	service, err := service.NewService(repository)
	if err != nil {
		return nil, fmt.Errorf("failed to create service. Error: %s", err)
	}
	handler := handlers.NewUserHandler(service)

	router := gin.Default()
	router.POST("/users", handler.CreateUser)
	router.POST("/login", handler.HandleLogin)

	// TODO: remove this, for testing purposes only
	router.POST("/token", handler.ValidateToken)

	return router, nil
}
