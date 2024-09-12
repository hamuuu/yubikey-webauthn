package handlers

import (
	"encoding/json"
	"net/http"
	"time"
	"yubikey/models"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Handler to generate a new TOTP secret
func RegisterOTPHandler(w http.ResponseWriter, r *http.Request) {
	user, err := models.GetUserByName(getUserNameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Generate a new TOTP secret key for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyApp",                             // Issuer name (e.g., your app name)
		AccountName: getUserNameFromContext(r.Context()), // The user account for whom the TOTP is being created
	})
	if err != nil {
		http.Error(w, "Failed to generate TOTP secret", http.StatusInternalServerError)
		return
	}

	// Extract the TOTP secret as a string
	user.TOTPSecret = key.Secret()
	models.UpdateUser(user)

	// Display the TOTP secret key for YubiKey configuration
	w.Write([]byte(user.TOTPSecret))
}

// Handler to verify a TOTP code entered by the user
func VerifyTOTPHandler(w http.ResponseWriter, r *http.Request) {
	// Get the OTP from the user input
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Otp      string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := models.GetUserByName(req.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if !models.CheckPasswordHash(req.Password, user.Password) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Validate the TOTP code based on the shared secret
	valid, err := totp.ValidateCustom(req.Otp, user.TOTPSecret, time.Now().UTC(), totp.ValidateOpts{
		Period:    60,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
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

func ProtectedHandlerWithOtp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Otp string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := models.GetUserByName(getUserNameFromContext(r.Context()))
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Validate the TOTP code based on the shared secret
	valid, err := totp.ValidateCustom(req.Otp, user.TOTPSecret, time.Now().UTC(), totp.ValidateOpts{
		Period:    60,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Welcome! You have accessed a protected route with OTP."))
}
