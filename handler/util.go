package handler

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func (s *server) createToken(userId uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
		"iat":    time.Now().Unix(),
		"userid": userId,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtKey := os.Getenv("JWTKEY")
	tokenString, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		s.log.Errorf("could not signed the token: %v", err)
		return "", err
	}
	return tokenString, nil
}

func (s *server) extractToken(req *http.Request) string {
	bearerToken := req.Header.Get("Authorization")
	token := strings.Split(bearerToken, " ")
	if len(token) != 2 {
		s.log.Errorf("incorrect token length: %v", token)
		return ""
	}
	return token[1]
}

// simple authenticate function, here it could also check if the user exist in db
func (s *server) authenticate(userName, password string) bool {
	fmt.Printf("username: %v && password: %v", userName, password)
	if userName == "madhvi" && password == "test" {
		return true
	}
	return false
}
