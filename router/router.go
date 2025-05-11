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
	router.POST("/biometric-login", handler.HandleBiometricLogin)
	router.GET("/users", handler.GetUsers)
	router.GET("/user/:id", handler.GetUser)
	router.PUT("/user/:id", handler.EditUser)
	router.GET("/check-email-exists/:email", handler.EmailExists)
	router.POST("/users/:id/push-token", handler.AddPushToken)
	router.POST("/users/:id/notifications", handler.NotifyUser)
	router.PUT("/users/:id/notification-settings", handler.SetUserNotificationSettings)
	router.GET("/users/:id/notification-settings", handler.GetUserNotificationSettings)

	router.POST("/admin-login", handler.HandleAdminLogin)
	router.POST("/admins", handler.CreateAdmin)
	router.PUT("/user/:id/block", handler.BlockUser)
	router.PUT("/user/:id/unblock", handler.UnblockUser)
	router.PUT("/user/:id/type/:type", handler.SetUserType)

	return router, nil
}
