package configs

import (
	"log"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	WebAuthn     *webauthn.WebAuthn
	SessionStore = make(map[string]*webauthn.SessionData)
	StoreMutex   = &sync.RWMutex{} // To handle concurrent access
)

func InitWebAuthn() {
	var err error
	WebAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Your App",                                                                                                         // Display Name for your site
		RPID:          "localhost",                                                                                                        // Generally the domain name for your site
		RPOrigins:     []string{"http://localhost:8080", "http://localhost:8090", "https://0135-2404-c0-5c60-00-a67-eb1.ngrok-free.app/"}, // Allowed origins for WebAuthn requests
	})
	if err != nil {
		log.Fatalf("Failed to initialize WebAuthn: %v", err)
	}

	log.Println("Web Auth initialized success")
}
