package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"log"

	"github.com/stretchr/testify/assert"
)

// TestService tests all the endpoints of the server in different situations,
// both checking for the happy path and the error path.
func TestService(t *testing.T) {
	host := os.Getenv("HOST")
	assert.NotEqual(t, "", host, "Missing required environment variable HOST")
	port := os.Getenv("PORT")
	assert.NotEqual(t, "", port, "Missing required environment variable PORT")
	url := "http://" + host + ":" + port + "/courses"
	logger := log.Default()
	t.Run("Create course", func(t *testing.T) {
		course := `{"title":"test title","description":"test description"}`

		logger.Println("Creating course 0")
		resp, err := http.Post(url, "application/json", strings.NewReader(course))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		expectedResponse := `{"data":{"title":"test title","description":"test description","id":0}}`
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()

		logger.Println("Course created successfully. Response: ", string(body))
	})

	t.Run("Get courses", func(t *testing.T) {
		logger.Println("Retrieving courses...")
		resp, err := http.Get(url)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		expectedResponse := `{"data":[{"title":"test title","description":"test description","id":0}]}`
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()
		logger.Println("Courses retrieved successfully. Response ", string(body))
	})

	t.Run("Get course with id 0", func(t *testing.T) {
		id := "0"
		logger.Println("Retrieving course with ID 0...")
		resp, err := http.Get(url + "/" + id)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		expectedResponse := `{"data":{"title":"test title","description":"test description","id":0}}`
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()
		logger.Println("Course retrieved successfully. Response: ", string(body))
	})

	t.Run("Check that an error is returned when requesting a non existing course", func(t *testing.T) {
		id := "1"
		logger.Println("Retrieving a non existing course...")
		resp, err := http.Get(url + "/" + id)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		expectedResponse := `{"detail":"The course with ID 1 was not found","instance":"/courses/1","status":404,"title":"Course not found","type":"about:blank"}`
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()
		logger.Println("Received the expected error: ", string(body))
	})

	t.Run("Check that courses are created with incremental IDs", func(t *testing.T) {
		course := `{"title":"test title 2","description":"test description 2"}`
		logger.Println("Creating a new course...")
		resp, err := http.Post(url, "application/json", strings.NewReader(course))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		expectedResponse := `{"data":{"title":"test title 2","description":"test description 2","id":1}}`
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()
		logger.Println("The new course has been assigned the right ID: ", string(body))
	})

	t.Run("Check that courses are returned in an inversed chronological order", func(t *testing.T) {
		logger.Println("Retrieving all the courses...")
		resp, err := http.Get(url)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		expectedResponse := `{"data":[{"title":"test title 2","description":"test description 2","id":1},{"title":"test title","description":"test description","id":0}]}`
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()
		logger.Println("The courses were returned in the right order (inversed chronologically): ", string(body))
	})

	t.Run("Delete course", func(t *testing.T) {
		logger.Println("Deleting the course with ID 0...")
		id := "0"
		client := &http.Client{}
		req, err := http.NewRequest("DELETE", url+"/"+id, nil)
		assert.NoError(t, err)

		resp, err := client.Do(req)
		assert.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		expectedResponse := ""
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()
		logger.Println("The course was deleted successfully")
	})

	t.Run("Check that deleting a non existing course returns an error", func(t *testing.T) {
		logger.Println("Trying to delete a non existing course...")
		id := "0"
		client := &http.Client{}
		req, err := http.NewRequest("DELETE", url+"/"+id, nil)
		assert.NoError(t, err)

		resp, err := client.Do(req)
		assert.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		expectedResponse := `{"detail":"The course with ID 0 was not found","instance":"/courses/0","status":404,"title":"Course not found","type":"about:blank"}`
		assert.Equal(t, expectedResponse, string(body))
		resp.Body.Close()
		logger.Println("Received the expected error: ", string(body))

	})
	logger.Print("Tests ran successfully!")
}
