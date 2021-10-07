package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/pmadhvi/go-auth-jwt/model"
)

func (s *server) GetTokenHandler(rw http.ResponseWriter, req *http.Request) {
	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Could not read the request body %v", err)
		s.log.Error(errMsg)
		respondErrorJSON(rw, 400, errMsg)
		return
	}
	var u model.User
	err = json.Unmarshal(reqBody, &u)
	if err != nil {
		errMsg := fmt.Sprintf("Could not unmarshal request body %v", err)
		s.log.Error(errMsg)
		respondErrorJSON(rw, 400, errMsg)
		return
	}

	if !s.authenticate(u.UserName, u.Password) {
		errMsg := fmt.Sprintf("Invalid user credential %v", err)
		s.log.Error(errMsg)
		respondErrorJSON(rw, 400, errMsg)
		return
	}
	token, err := s.createToken(uuid.New())
	if err != nil {
		errMsg := fmt.Sprintf("could not generate token %v", err)
		s.log.Error(errMsg)
		respondErrorJSON(rw, 400, errMsg)
		return
	}
	respondSuccessJSON(rw, 200, token)
}

func (s *server) Middleware(next http.Handler) http.Handler {
	fmt.Println("Hello inside middleware")
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		tokenStr := s.extractToken(req)
		token, _ := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				errMsg := fmt.Sprintf("Invalid signing method %v", token.Header["alg"])
				s.log.Error(errMsg)
				return nil, fmt.Errorf(errMsg)
			}
			return []byte(os.Getenv("JWTKEY")), nil
		})

		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			ctx := context.WithValue(req.Context(), "props", claims)
			next.ServeHTTP(rw, req.WithContext(ctx))
			return
		}
		errMsg := "Unauthroized"
		respondErrorJSON(rw, 401, errMsg)
	})
}

func (s *server) LoginHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Println("Inside login")
	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Could not read the request body %v", err)
		s.log.Error(errMsg)
		respondErrorJSON(rw, 400, errMsg)
		return
	}
	var u model.User
	err = json.Unmarshal(reqBody, &u)
	if err != nil {
		errMsg := fmt.Sprintf("Could not unmarshal request body %v", err)
		s.log.Error(errMsg)
		respondErrorJSON(rw, 400, errMsg)
		return
	}
	respondSuccessJSON(rw, 200, "Successfull Login")
}

func respondSuccessJSON(rw http.ResponseWriter, statusCode int, response interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)
	json.NewEncoder(rw).Encode(response)
}

func respondErrorJSON(rw http.ResponseWriter, errorCode int, errorMsg interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(errorCode)
	json.NewEncoder(rw).Encode(errorMsg)
}
