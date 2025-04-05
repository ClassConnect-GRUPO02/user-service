package main

import (
	"log"
)

func main() {
	host, err := GetEnvVar("HOST")
	if err != nil {
		log.Fatal("Error: ", err)
	}
	port, err := GetEnvVar("PORT")
	if err != nil {
		log.Fatal("Error: ", err)
	}
	environment, err := GetEnvVar("ENVIRONMENT")
	if err != nil {
		log.Fatal("Error: ", err)
	}

	log.Println("Enviroment: ", environment)
	StartService(host, port)
}
