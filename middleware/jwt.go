package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var jwtSecretKey = []byte("your_secret_key")

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Parse and validate JWT token
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		log.Printf("%+v", claims)
		// Store user ID from token in request context
		r = r.WithContext(context.WithValue(r.Context(), "userID", claims.Subject))

		// Proceed to the next handler
		next.ServeHTTP(w, r)
	})
}
