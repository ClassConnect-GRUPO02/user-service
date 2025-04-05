package utils

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
