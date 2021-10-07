package handler

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type server struct {
	log  *logrus.Logger
	port string
}

func NewServer(log *logrus.Logger, port string) *server {
	return &server{
		log:  log,
		port: port,
	}
}
func (s *server) Start() error {
	router := mux.NewRouter()
	loginHandler := http.HandlerFunc(s.LoginHandler)
	// logging middleware is used in all request
	router.Use(s.LoggingMiddleware)
	router.HandleFunc("/jwt/getToken", s.GetTokenHandler).Methods("POST")

	// Making use of ValidToken(which is a middleware) to test the validity of token on all request except Get token
	router.Handle("/jwt/login", s.ValidateTokenMiddleware(loginHandler)).Methods("POST")
	err := http.ListenAndServe(fmt.Sprintf(":%s", s.port), router)
	if err != nil {
		s.log.Errorf("Could not start the server: %v", err)
		return err
	}
	return nil
}
