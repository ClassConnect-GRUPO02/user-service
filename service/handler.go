package main

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// CreateCourseHandler is the handler for the 'POST /courses' endpoint.
// It creates a new course with the given title and description.
// If the request is wrong, it responds a 400 error.
func CreateCourseHandler(c *gin.Context, state *State) {
	log.Print("Received create course request")
	course := Course{}
	if err := c.ShouldBind(&course); err != nil {
		log.Print("Error: Bad request")
		c.JSON(http.StatusBadRequest, gin.H{
			"title":    "Bad request",
			"type":     "about:blank",
			"status":   http.StatusBadRequest,
			"detail":   "Could not create the course",
			"instance": "/courses",
		})
		return
	}
	course.Id = state.IdCounter

	// Store the course
	state.Courses = append(state.Courses, course)

	c.JSON(http.StatusCreated, gin.H{
		"data": course,
	})

	// Increment the counter
	state.IdCounter += 1
}

// GetCoursesHandler is the handler for the 'GET /courses' endpoint.
// It responds an array containing all the courses.
func GetCoursesHandler(c *gin.Context, state *State) {
	log.Print("Received a get courses request")
	c.JSON(http.StatusCreated, gin.H{
		"data": ReverseCourses(state.Courses),
	})
}

// GetCourseHandler is the handler for the 'GET /courses/{id}' endpoint.
// On success, it returns the requested course.
// If the course does not exist, it responds with a 404 error.
func GetCourseHandler(c *gin.Context, state *State) {
	id := c.Param("id")
	log.Printf("Received a request to get the course with id %s", id)
	// Search for the course
	for _, course := range state.Courses {
		courseId := strconv.Itoa(int(course.Id))
		if courseId == id {
			log.Printf("Returning the information of the course with id %s", id)
			c.JSON(http.StatusCreated, gin.H{
				"data": course,
			})
			return
		}
	}
	log.Printf("Error: Course with id %s not found", id)
	c.JSON(http.StatusNotFound, gin.H{
		"title":    "Course not found",
		"type":     "about:blank",
		"status":   http.StatusNotFound,
		"detail":   "The course with ID " + id + " was not found",
		"instance": "/courses/" + id,
	})
}

// DeleteCourseHandler is the handler for the 'DELETE /courses/{id}' endpoint.
// It deletes the given course. If the course does not exist, it responds with a 404 error.
func DeleteCourseHandler(c *gin.Context, state *State) {
	id := c.Param("id")
	log.Printf("Received a request to delete the course with id %s", id)
	// Search for the course
	for index, course := range state.Courses {
		courseId := strconv.Itoa(int(course.Id))
		if courseId == id {
			// Remove the course from the array
			log.Printf("Course %s deleted successfully", id)
			state.Courses = RemoveCourseWithIndex(state.Courses, index)
			c.JSON(http.StatusNoContent, nil)
			return
		}
	}
	log.Printf("Error: Course with id %s not found", id)
	c.JSON(http.StatusNotFound, gin.H{
		"title":    "Course not found",
		"type":     "about:blank",
		"status":   http.StatusNotFound,
		"detail":   "The course with ID " + id + " was not found",
		"instance": "/courses/" + id,
	})
}
