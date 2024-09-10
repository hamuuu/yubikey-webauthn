package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"yubikey/configs"
	"yubikey/models"

	"github.com/dgrijalva/jwt-go"
)

func RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if the user already exists
	if _, err := models.GetUserByName(req.Username); err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash the password
	hashedPassword, err := models.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Generate a user ID
	userID, err := models.GenerateUserID(req.Username)
	if err != nil {
		http.Error(w, "Failed to generate user ID", http.StatusInternalServerError)
		return
	}

	// Create the user object
	user := &models.User{
		ID:          userID,
		Name:        req.Username,
		DisplayName: req.Username,
		Password:    hashedPassword,
	}

	// Save the user to the database
	if err := models.SaveUser(user); err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func RegisterWebAuthnHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch the user from the database
	user, err := models.GetUserByName(getUserNameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Initiate WebAuthn registration
	options, sessionData, err := configs.WebAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "Failed to initiate WebAuthn registration", http.StatusInternalServerError)
		return
	}

	// Store session data for WebAuthn
	configs.StoreMutex.Lock()
	configs.SessionStore[string(user.ID)] = sessionData
	configs.StoreMutex.Unlock()

	// Send the registration options to the client
	json.NewEncoder(w).Encode(options)
}

func FinishRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the user from the database
	user, err := models.GetUserByName(getUserNameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Retrieve the session data from the in-memory store
	configs.StoreMutex.RLock()
	sessionData, exists := configs.SessionStore[string(user.ID)]
	configs.StoreMutex.RUnlock()
	if !exists {
		http.Error(w, "Session data not found", http.StatusBadRequest)
		return
	}

	// Finish the WebAuthn registration
	credential, err := configs.WebAuthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		log.Println("here : " + err.Error())
		http.Error(w, "Failed to finish registration", http.StatusInternalServerError)
		return
	}

	// Add the new credential to the user and update the database
	user.AddCredential(*credential)
	if err := models.UpdateUser(user); err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Registration successful"))
}

func BeginLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Fetch user from the database
	user, err := models.GetUserByName(req.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// User doesn't have WebAuthn credentials, proceed with password authentication
	if !models.CheckPasswordHash(req.Password, user.Password) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Check if the user has WebAuthn credentials in the database
	if len(user.Credentials) > 0 {
		// User has WebAuthn credentials, begin WebAuthn login
		options, sessionData, err := configs.WebAuthn.BeginLogin(user)
		if err != nil {
			http.Error(w, "Failed to initiate WebAuthn login", http.StatusInternalServerError)
			return
		}

		// Store WebAuthn session data
		configs.StoreMutex.Lock()
		configs.SessionStore[string(user.ID)] = sessionData
		configs.StoreMutex.Unlock()

		// Send WebAuthn options to the client
		json.NewEncoder(w).Encode(options)
	} else {

		// Password authentication successful, proceed with JWT or other session handling
		token, err := generateJWT(user)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

func FinishLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}

	// Read the body into a buffer
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Reset the request body so it can be read again
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := models.GetUserByName(req.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Retrieve the session data from the in-memory store
	configs.StoreMutex.RLock()
	sessionData, exists := configs.SessionStore[string(user.ID)]
	configs.StoreMutex.RUnlock()
	if !exists {
		http.Error(w, "Session data not found", http.StatusBadRequest)
		return
	}

	// Finish the WebAuthn login
	_, err = configs.WebAuthn.FinishLogin(user, *sessionData, r)
	if err != nil {
		log.Println("error : " + err.Error())
		http.Error(w, "Failed to finish login", http.StatusInternalServerError)
		return
	}

	// Generate JWT token
	tokenString, err := generateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"token":"` + tokenString + `"}`))
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome! You have accessed a protected route."))
}

func ProtectedHandlerWebAuthnStart(w http.ResponseWriter, r *http.Request) {
	// Fetch user from the database
	user, err := models.GetUserByName(getUserNameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	options, sessionData, err := configs.WebAuthn.BeginLogin(user)
	if err != nil {
		http.Error(w, "Failed to initiate WebAuthn login", http.StatusInternalServerError)
		return
	}

	// Store WebAuthn session data
	configs.StoreMutex.Lock()
	configs.SessionStore[string(user.ID)] = sessionData
	configs.StoreMutex.Unlock()
	json.NewEncoder(w).Encode(options)
}

func ProtectedHandlerWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserByName(getUserNameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Retrieve the session data from the in-memory store
	configs.StoreMutex.RLock()
	sessionData, exists := configs.SessionStore[string(user.ID)]
	configs.StoreMutex.RUnlock()
	if !exists {
		http.Error(w, "Session data not found", http.StatusBadRequest)
		return
	}

	// Finish the WebAuthn login
	_, err = configs.WebAuthn.FinishLogin(user, *sessionData, r)
	if err != nil {
		log.Println("error : " + err.Error())
		http.Error(w, "Failed to finish login", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hit protected endpoint with webauthn successfully"))
}

var jwtSecretKey = []byte("your_secret_key")

// Function to generate JWT
func generateJWT(user *models.User) (string, error) {
	// Set token expiration time
	expirationTime := time.Now().Add(24 * time.Hour)

	// Create JWT claims, which includes the username and expiry time
	claims := &jwt.StandardClaims{
		Subject:   string(user.Name),
		ExpiresAt: expirationTime.Unix(),
	}

	// Create the token using the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func getUserNameFromContext(ctx context.Context) string {
	userName, ok := ctx.Value("userName").(string)
	if !ok {
		// Handle the case where the value is not present or not of the expected type
		return ""
	}
	return userName
}
