package utils

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"math/rand/v2"
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

func GetIntEnvVar(envVar string) (int64, error) {
	variableString, err := GetEnvVar(envVar)
	if err != nil {
		return 0, fmt.Errorf("missing environment variable %s", envVar)
	}
	variableInt, err := strconv.ParseInt(variableString, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to convert %s to uint64. Error: %s", variableString, err)
	}
	return variableInt, nil
}

func GetDate() string {
	return time.Now().Format("2006-01-02")
}

func GetVerificationMessage(email string, pin int) string {
	message := fmt.Sprintf(
		`Hola, %s.
Gracias por registrarte en ClassConnect. Para verificar tu correo, utiliza el siguiente código:  %d
Si no solicitaste este código, por favor ignora este mensaje.

¡Bienvenido/a!
El equipo de ClassConnect`, email, pin)
	return message
}

func GenerateRandomNumber() int {
	min := 100000
	max := 999999
	return rand.IntN(max-min) + min
}
