package router

import (
	"github.com/gin-gonic/gin"
)

// CreateRouter creates the router exposing the endpoints
func CreateRouter(host, port string) *gin.Engine {
	router := gin.Default()

	// TODO: add state (or db) and set endpoints
	return router
}
