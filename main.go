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
	http.Handle("/protected/webauthn/start", middleware.JWTMiddleware(http.HandlerFunc(handlers.ProtectedHandlerWebAuthnStart)))
	http.Handle("/protected/webauthn/finish", middleware.JWTMiddleware(http.HandlerFunc(handlers.ProtectedHandlerWebAuthnFinish)))
	http.HandleFunc("/register", handlers.RegisterUserHandler)
	http.Handle("/webauthn/register/start", middleware.JWTMiddleware(http.HandlerFunc(handlers.RegisterWebAuthnHandler)))
	http.Handle("/webauthn/register/finish", middleware.JWTMiddleware(http.HandlerFunc(handlers.FinishRegistrationHandler)))
	http.HandleFunc("/login", handlers.BeginLoginHandler)
	http.HandleFunc("/login/finish", handlers.FinishLoginHandler)
	http.Handle("/otp/register/start", middleware.JWTMiddleware(http.HandlerFunc(handlers.RegisterOTPHandler)))
	http.HandleFunc("/login/otp", handlers.VerifyTOTPHandler)
	http.Handle("/encrypt-file", middleware.JWTMiddleware(http.HandlerFunc(handlers.UploadFileHandlerEncrypt)))
	http.Handle("/decrypt-file", middleware.JWTMiddleware(http.HandlerFunc(handlers.UploadFileHandlerDecrypt)))

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
