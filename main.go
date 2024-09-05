package main

import (
	"log"
	"net/http"
	"yubikey/configs"
	"yubikey/handlers"
	"yubikey/middleware"

	gorilla "github.com/gorilla/handlers"
)

func main() {
	configs.InitMongoDB()
	configs.InitWebAuthn()

	http.Handle("/", http.FileServer(http.Dir("./client")))
	http.Handle("/protected", middleware.JWTMiddleware(http.HandlerFunc(handlers.ProtectedHandler)))
	http.Handle("/protected/otp", middleware.JWTMiddleware(http.HandlerFunc(handlers.ProtectedHandlerWithOtp)))
	http.Handle("/protected/webauthn", middleware.JWTMiddleware(http.HandlerFunc(handlers.ProtectedHandler)))
	http.HandleFunc("/register", handlers.RegisterHandler)
	http.HandleFunc("/register/finish", handlers.FinishRegistrationHandler)
	http.HandleFunc("/login/begin", handlers.BeginLoginHandler)
	http.HandleFunc("/login/finish", handlers.FinishLoginHandler)
	http.HandleFunc("/generate-totp", handlers.GenerateTOTPHandler)
	http.HandleFunc("/login/otp", handlers.VerifyTOTPHandler)

	// CORS configuration
	corsHeaders := gorilla.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	corsOrigins := gorilla.AllowedOrigins([]string{"*"}) // Allow your origin
	corsMethods := gorilla.AllowedMethods([]string{"GET", "POST", "OPTIONS"})

	// Wrap your gorilla with CORS middleware
	handler := gorilla.CORS(corsHeaders, corsOrigins, corsMethods)(http.DefaultServeMux)

	// Start the server
	log.Println("Web Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", handler))

}
