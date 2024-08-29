package main

import (
	"log"
	"net/http"
	"yubikey/middleware"
	"yubikey/models"

	"github.com/gorilla/handlers"
)

func main() {
	models.InitMongoDB()
	models.InitWebAuthn()

	http.Handle("/protected", middleware.JWTMiddleware(http.HandlerFunc(models.ProtectedHandler)))
	http.Handle("/protected/webauthn", middleware.JWTMiddleware(http.HandlerFunc(models.ProtectedHandler)))
	http.HandleFunc("/register", models.RegisterHandler)
	http.HandleFunc("/register/finish", models.FinishRegistrationHandler)
	http.HandleFunc("/login/begin", models.BeginLoginHandler)
	http.HandleFunc("/login/finish", models.FinishLoginHandler)

	// CORS configuration
	corsHeaders := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	corsOrigins := handlers.AllowedOrigins([]string{"*"}) // Allow your origin
	corsMethods := handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS"})

	// Wrap your handlers with CORS middleware
	handler := handlers.CORS(corsHeaders, corsOrigins, corsMethods)(http.DefaultServeMux)

	// Start the server
	log.Println("Web Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", handler))

}
