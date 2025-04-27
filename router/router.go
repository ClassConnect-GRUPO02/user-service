package router

import (
	"user_service/handlers"

	"github.com/gin-gonic/gin"
)

// CreateUserRouter creates the router exposing the endpoints
func CreateUserRouter(handler *handlers.UserHandler) (*gin.Engine, error) {
	router := gin.Default()
	router.POST("/users", handler.CreateUser)
	router.POST("/login", handler.HandleLogin)
	router.GET("/users", handler.GetUsers)
	router.GET("/user/:id", handler.GetUser)

	return router, nil
}
