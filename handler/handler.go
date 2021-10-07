package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/pmadhvi/go-auth-jwt/model"
	"github.com/sirupsen/logrus"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (lwr loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := lwr.ResponseWriter.Write(b)
	lwr.size += size
	return size, err
}

func (lwr loggingResponseWriter) WriteHeader(statusCode int) {
	lwr.ResponseWriter.WriteHeader(statusCode)
	lwr.statusCode = statusCode
}

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

	// Basic authentication of username and password
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

// ValidToken is an middleware which validates jwt token
// passed in request header and futher excutes the next handler
func (s *server) ValidateTokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		tokenStr := s.extractToken(req)
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				errMsg := fmt.Sprintf("Invalid signing method %v", token.Header["alg"])
				s.log.Error(errMsg)
				return nil, fmt.Errorf(errMsg)
			}
			return []byte(os.Getenv("JWTKEY")), nil
		})
		if err != nil {
			s.log.Errorf("could not parse token due to error %v", err)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			s.log.Errorf("Unauthroized")
			return
		}
		ctx := context.WithValue(req.Context(), "claims", claims)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// This middle logs request and response parameters
func (s *server) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		//handle the error logging in case of error or panic
		defer func() {
			if err := recover(); err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				s.log.WithFields(logrus.Fields{
					"error": err,
					"trace": debug.PrintStack,
				}).Error("error when recovering from panic")
			}
		}()
		// This part will log the request and response parameters,
		// without logging req and resp body
		start := time.Now()
		lrw := loggingResponseWriter{
			ResponseWriter: rw,
			size:           0,
			statusCode:     0,
		}
		request_id := uuid.New()
		ctx := req.Context()
		ctx = context.WithValue(ctx, "request_id", request_id)
		req.WithContext(ctx)
		method := req.Method
		host := req.Host
		uri := req.URL.EscapedPath()

		//lrw is ResponseWriter with more fileds used for logging
		next.ServeHTTP(&lrw, req)

		s.log.WithFields(logrus.Fields{
			"Request ID":          request_id,
			"Method":              method,
			"Request URL":         uri,
			"Request Host":        host,
			"Duration":            time.Since(start),
			"Response StatusCode": lrw.statusCode,
			"Response Size":       lrw.size,
		}).Info("Request::")
	})
}

func (s *server) LoginHandler(rw http.ResponseWriter, req *http.Request) {
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
	fmt.Println(req.Context().Value("cliams"))
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
