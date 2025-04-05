package main

import (
	"log"
	"user_service/router"
	"user_service/utils"
)

func main() {
	host, err := utils.GetEnvVar("HOST")
	if err != nil {
		log.Fatal("Error: ", err)
	}
	port, err := utils.GetEnvVar("PORT")
	if err != nil {
		log.Fatal("Error: ", err)
	}
	environment, err := utils.GetEnvVar("ENVIRONMENT")
	if err != nil {
		log.Fatal("Error: ", err)
	}
	log.Println("Enviroment: ", environment)
	router := router.CreateRouter(host, port)
	router.Run()
}
