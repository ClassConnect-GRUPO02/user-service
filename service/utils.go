package main

import (
	"errors"
	"os"
)

// GetEnvVar reads the value of the given variable from the enviroment and returns it.
// If the variable is not set, it returns an error.
func GetEnvVar(variable string) (string, error) {
	value := os.Getenv(variable)
	if value == "" {
		return "", errors.New("Missing required environment variable " + variable)
	}
	return value, nil
}

// Receives an array of courses and returns an array of courses in the inverse order.
func ReverseCourses(courses []Course) []Course {
	lenCourses := len(courses)
	reversedCourses := make([]Course, lenCourses)
	for i := 0; i < len(courses); i++ {
		reversedCourses[i] = courses[lenCourses-1-i]
	}
	return reversedCourses
}

// Receives an array of courses and removes the course at the given index.
func RemoveCourseWithIndex(courses []Course, index int) []Course {
	return append(courses[:index], courses[index+1:]...)
}
