package handler

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

type server struct {
	log  *log.Logger
	port string
}

func NewServer(log *log.Logger, port string) *server {
	return &server{
		log:  log,
		port: port,
	}
}
func (s *server) Start() error {
	router := mux.NewRouter()
	loginHandler := http.HandlerFunc(s.LoginHandler)

	router.HandleFunc("/jwt/getToken", s.GetTokenHandler).Methods("POST")
	router.Handle("/jwt/login", s.Middleware(loginHandler)).Methods("POST")
	err := http.ListenAndServe(fmt.Sprintf(":%s", s.port), router)
	if err != nil {
		s.log.Errorf("Could not start the server: %v", err)
		return err
	}
	return nil
}
