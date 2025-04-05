package main

import (
	"github.com/gin-gonic/gin"
)

// StartService starts the http server which listens for requests in the given host and port.
func StartService(host, port string) {
	r := gin.Default()
	state := State{
		Courses:   make([]Course, 0),
		IdCounter: uint64(0),
	}

	r.POST("/courses", func(c *gin.Context) {
		CreateCourseHandler(c, &state)
	})

	r.GET("/courses", func(c *gin.Context) {
		GetCoursesHandler(c, &state)
	})

	r.GET("/courses/:id", func(c *gin.Context) {
		GetCourseHandler(c, &state)
	})

	r.DELETE("/courses/:id", func(c *gin.Context) {
		DeleteCourseHandler(c, &state)
	})

	address := host + ":" + port
	r.Run(address)
}
