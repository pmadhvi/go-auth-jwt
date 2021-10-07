package main

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/pmadhvi/go-auth-jwt/handler"
	"github.com/sirupsen/logrus"
)

func main() {
	// setup the log
	var log = logrus.New()
	log.SetOutput(os.Stdout)

	// read .env file for env variables
	err := godotenv.Load()
	if err != nil {
		log.Errorf("Error loading .env file %v", err)
	}
	// read the env variables from .env file
	port := os.Getenv("PORT")
	if port == "" {
		log.Info("port env variable not set, so using default port 8080")
		port = "8080"
	}

	server := handler.NewServer(log, port)
	errChan := make(chan error)
	go func() {
		log.Info("server started")
		errChan <- server.Start()
	}()

	// get errors from chan and exit the application
	if err := <-errChan; err != nil {
		log.Info(err)
		os.Exit(1)
	}
}
