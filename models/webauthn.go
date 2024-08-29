package models

import (
	"log"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn     *webauthn.WebAuthn
	sessionStore = make(map[string]*webauthn.SessionData)
	storeMutex   = &sync.RWMutex{} // To handle concurrent access
)

func InitWebAuthn() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Your App",                                                                                                         // Display Name for your site
		RPID:          "localhost",                                                                                                        // Generally the domain name for your site
		RPOrigins:     []string{"http://localhost:8080", "http://localhost:8090", "https://0135-2404-c0-5c60-00-a67-eb1.ngrok-free.app/"}, // Allowed origins for WebAuthn requests
	})
	if err != nil {
		log.Fatalf("Failed to initialize WebAuthn: %v", err)
	}

	log.Println("Web Auth initialized success")
}
