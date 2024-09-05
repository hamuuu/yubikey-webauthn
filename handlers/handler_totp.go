package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"yubikey/models"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var totpSecret string = "Y33SBSB66NKXQDT5WDUVCB5QYZ73LJEU"

// Handler to generate a new TOTP secret
func GenerateTOTPHandler(w http.ResponseWriter, r *http.Request) {
	// Generate a new TOTP secret key for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyApp",                           // Issuer name (e.g., your app name)
		AccountName: "mochamad.satria@spesolution.com", // The user account for whom the TOTP is being created
	})
	if err != nil {
		http.Error(w, "Failed to generate TOTP secret", http.StatusInternalServerError)
		return
	}

	// Extract the TOTP secret as a string
	totpSecret = key.Secret()

	// Display the TOTP secret key for YubiKey configuration
	fmt.Fprintf(w, "Your TOTP secret is: %s\n", totpSecret)
	fmt.Fprintf(w, "Scan this in Yubico Authenticator to configure your YubiKey.\n")
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

	// Validate the TOTP code based on the shared secret
	valid, err := totp.ValidateCustom(req.Otp, totpSecret, time.Now().UTC(), totp.ValidateOpts{
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

	// Validate the TOTP code based on the shared secret
	valid, err := totp.ValidateCustom(req.Otp, totpSecret, time.Now().UTC(), totp.ValidateOpts{
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
