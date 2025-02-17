
# Implement Yubikey in Web App

Dalam pengimplementasian Yubikey pada aplikasi Web App, Yubikey biasanya digunakan untuk melakukan Two-Factor Authentication (2FA) atau autentikasi lainnya yang di support oleh Yubikey. Berikut pendekatan dalam mengimplementasikan Yubikey di Web App dan mengkombinasikan 2FA dengan JWT (Json Web Token) yang pada dokumentasi ini akan menggunakan golang sebagai bahasa pemrograman untuk membuat Web App.

### Prerequisites

- Yubikey 5C.
- Golang terinstall di komputer.
- MongoDB

### Project Structure

Dalam mengimplementasikan Yubikey ke dalam Web App, dalam dokumentasi ini memakai stack Go untuk backend nya dan html untuk frontend. Untuk struktur dari folder sendiri, dapat dilihat pada gambar dibawah. 

> ![file](./assets/yubikey-1-1.png)


### Setup Instruction

#### 1. Buat Folder Project

Buat folder baru untuk project integrasi Yubikey dengan web application:

<pre>
mkdir yubikey
cd yubikey
</pre>

#### 2. Init go module dan install dependencies

Jalankan perintah berikut untuk melakukan inisiasi go module dan install dependencies library yang akan digunakan.

<pre>
````
go mod init your_project_name
go get github.com/go-webauthn/webauthn/webauthn
go get github.com/dgrijalva/jwt-go
````
</pre>

#### 3. Buat file configs/webauthn.go

Buat file configs/webauthn.go yang berisi inisiasi dari library webauthn sebagai metode autentikasi dari web app.

<pre>
````
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
````
</pre>

#### 4. Buat file configs/mongodb.go

Buat file configs/mongo.go yang berisi inisiasi connection ke mongodb untuk memvalidasi dan menyimpan user yang akan di daftarkan nanti.

<pre>
````
package configs

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var UserCollection *mongo.Collection

func InitMongoDB() {
	clientOptions := options.Client().ApplyURI("mongodb://username:password@127.0.0.1:27018")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		panic(err)
	}

	UserCollection = client.Database("db_name").Collection("users")
	log.Println("Mongo initialized success")
}
````
</pre>

#### 5. Buat file models/user.go

Buat file models/users.go berisi pendefinisan struct user yang akan menampung data user yang di akan di get/store pada database dan fungsi fungsi pendukung untuk menjembatani app dengan collection users pada mongodb.

<pre>
````
package models

import (
	"context"
	"yubikey/configs"

	"github.com/go-webauthn/webauthn/webauthn"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID          []byte                `bson:"_id,omitempty"`
	Name        string                `bson:"name"`
	DisplayName string                `bson:"display_name"`
	Password    string                `bson:"password"`
	Credentials []webauthn.Credential `bson:"credentials"`
	TOTPSecret  string                `bson:"totp_secret"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GetUserByName(name string) (*User, error) {
	var user User
	err := configs.UserCollection.FindOne(context.TODO(), bson.M{"name": name}).Decode(&user)
	return &user, err
}

func SaveUser(user *User) error {
	_, err := configs.UserCollection.InsertOne(context.TODO(), user)
	return err
}

func UpdateUser(user *User) error {
	_, err := configs.UserCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": user.ID},
		bson.M{"$set": user},
	)
	return err
}

func (u *User) WebAuthnID() []byte {
	return u.ID
}

func (u *User) WebAuthnName() string {
	return u.Name
}

func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

func GenerateUserID(name string) ([]byte, error) {
	return []byte(name), nil
}
````
</pre>

#### 5. Buat file handlers/handler_fido.go

Buat file handlers/handler_fido.go untuk mendefinisikan handler dari metode autentikasi FIDO2.

<pre>
````
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
````
</pre>

Penjelasan fungsi fungsi diatas:

- **RegisterUserHandler**

Fungsi: Menangani registrasi pengguna baru.

1. Menerima data username dan password dari request body.
2. Mengecek apakah pengguna sudah ada di database.
3. Jika belum ada, password akan di-hash dan userID di-generate.
4. Kemudian pengguna baru akan disimpan ke database.

- **RegisterWebAuthnHandler**

Fungsi ini untuk memulai proses registrasi WebAuthn.

1. Mengambil data pengguna dari database menggunakan nama pengguna yang diperoleh dari context.
2. Memulai proses registrasi WebAuthn dan menyimpan sessionData ke dalam SessionStore.
3. Mengembalikan opsi WebAuthn untuk registrasi ke klien.

- **FinishRegistrationHandler**

Fungsi ini menyelesaikan proses registrasi WebAuthn.

1. Mengambil pengguna dari database dan sessionData dari SessionStore.
2. Menyelesaikan registrasi WebAuthn.
3. Jika sukses, menambahkan credential baru ke pengguna dan memperbarui database.

- **BeginLoginHandler**

Fungsi ini memulai proses login.

1. Menerima username dan password.
2. Mengecek apakah pengguna ada dan apakah password sesuai.
3. Jika pengguna memiliki credential WebAuthn, proses login WebAuthn dimulai.
4. Jika tidak ada credential WebAuthn, autentikasi menggunakan password dan JWT dihasilkan sebagai token sesi.

- **FinishLoginHandler**

Fungsi ini menyelesaikan proses login WebAuthn.

1. Mengambil pengguna dan sessionData dari SessionStore.
2. Menyelesaikan login WebAuthn.
3. Jika login sukses, JWT dihasilkan dan dikirim sebagai respons.

- **ProtectedHandler**

Fungsi ini menangani permintaan ke rute yang dilindungi, hanya dapat diakses oleh pengguna yang berhasil diautentikasi.

- **ProtectedHandlerWebAuthnStart**

Fungsi ini memulai proses otentikasi WebAuthn untuk endpoint yang dilindungi.

1. Mengambil data pengguna dari context.
2. Memulai proses otentikasi WebAuthn dan menyimpan sessionData.
3. Mengembalikan opsi WebAuthn ke klien.

- **ProtectedHandlerWebAuthnFinish**

Fungsi ini menyelesaikan proses otentikasi WebAuthn pada endpoint yang dilindungi:

1. Mengambil pengguna dan sessionData dari SessionStore.
2. Menyelesaikan otentikasi WebAuthn.
3. Mengembalikan respons sukses jika otentikasi berhasil.

- **generateJWT**

Fungsi ini untuk menghasilkan token JWT:

1. Menggunakan informasi pengguna dan menetapkan waktu kedaluwarsa token (24 jam).
2. JWT dibuat dengan menggunakan HS256 sebagai metode penandatanganan dan ditandatangani menggunakan kunci rahasia (jwtSecretKey).
3. Mengembalikan token JWT yang sudah ditandatangani.

- **getUserNameFromContext**

Fungsi ini untuk mengambil nama pengguna dari context:

1. Mengambil nilai dari context yang diharapkan berupa userName.
2. Mengembalikan nama pengguna atau string kosong jika data tidak ditemukan.


#### 6. Buat file handlers/handler_otp.go

Buat file handlers/handler_otp.go untuk mendefinisikan handler dari metode autentikasi OTP.

<pre>
```
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
```
</pre>

Berikut penjelasan dari fungsi fungsi diatas

- **RegisterOTPHandler**

Fungsi ini digunakan untuk menghasilkan TOTP secret baru bagi pengguna:

1. Mengambil data pengguna dari database berdasarkan nama pengguna yang ada di context.
2. Menggunakan library totp.Generate untuk membuat TOTP secret yang unik bagi pengguna. Issuer diatur sebagai nama aplikasi (MyApp) dan AccountName sebagai nama akun pengguna.
3. Setelah TOTP secret dihasilkan, secret disimpan di objek pengguna dan diperbarui di database.
4. TOTP secret dikembalikan dalam response, yang biasanya akan digunakan untuk dikonfigurasi di perangkat pengguna seperti YubiKey atau aplikasi otentikasi lainnya.

- **VerifyTOTPHandler**

Fungsi ini digunakan untuk memverifikasi kode TOTP yang dimasukkan oleh pengguna:

1. Menerima username, password, dan kode OTP dari body request.
2. Mengecek apakah pengguna ada di database.
3. Mengecek apakah password yang dimasukkan sesuai dengan hash password yang tersimpan di database.
4. Jika password benar, fungsi memvalidasi kode OTP yang dimasukkan pengguna berdasarkan TOTP secret pengguna dan waktu sekarang.
5. Menggunakan totp.ValidateCustom dengan parameter Period (60 detik), Skew (toleransi kesalahan waktu 0 detik), Digits (6 digit kode OTP), dan Algorithm (SHA1) untuk memvalidasi OTP.
6. Jika valid, fungsi menghasilkan token JWT untuk sesi pengguna, dan mengirimkannya dalam respons.

- **ProtectedHandlerWithOtp**

Fungsi ini mengamankan endpoint yang hanya dapat diakses jika pengguna memasukkan OTP yang valid:

1. Menerima OTP dari body request.
2. Mengambil data pengguna dari database berdasarkan nama pengguna yang disimpan di context.
3. Memvalidasi OTP yang dimasukkan menggunakan TOTP secret pengguna yang tersimpan.
3. Jika valid, fungsi mengembalikan respons yang menunjukkan bahwa pengguna berhasil mengakses route yang dilindungi dengan OTP.


#### 7. Buat File middleware/jwt.go

Berisi fungsi yang akan berperan sebagai middleware untuk mengautentikasi request API ke endpoint yang di lindungi.

<pre>
```
package middleware

import (
	"context"
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
		// Store user ID from token in request context
		r = r.WithContext(context.WithValue(r.Context(), "userName", claims.Subject))

		// Proceed to the next handler
		next.ServeHTTP(w, r)
	})
}
```
</pre>

#### 7. Buat File main.go

Berfungsi sebagai entry point untuk aplikasi web, disini juga inisiasi terhadap third-party juga dilakukan, dalam hal ini yaitu MongoDB dan WebAuthn.

<pre>
```
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

```
</pre>

#### 8. Buat File HTML Client-Side

Di file ini terdapat html simpel yang digunakan untuk berinteraksi dengan web server yang terintegrasi dengan WebAuthn.

<pre>
```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login/Register</title>
    <script src="https://webauthn.io/static/js/simplewebauthn-browser.8.2.1.umd.min.js"></script>
    <style>
      body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
      }

      .container {
        background-color: #fff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        width: 300px;
      }

      h1 {
        text-align: center;
        color: #333;
      }

      form {
        display: flex;
        flex-direction: column;
      }

      label {
        margin-bottom: 5px;
        color: #555;
      }

      input[type="text"],
      #otp-field,
      input[type="password"] {
        padding: 8px;
        margin-bottom: 15px;
        border: 1px solid #ddd;
        border-radius: 4px;
      }

      button {
        padding: 10px;
        background-color: #28a745;
        color: #fff;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        margin-bottom: 10px;
      }

      button:hover {
        background-color: #218838;
      }

      .toggle-action {
        display: flex;
        justify-content: center;
        margin-bottom: 20px;
      }

      .toggle-action label {
        margin: 0 10px;
        color: #333;
        cursor: pointer;
      }

      .logged-in-message {
        text-align: center;
      }

      .logged-in-message p {
        margin-bottom: 20px;
        color: #333;
      }

      .logged-in-message button {
        background-color: #007bff;
      }

      .logged-in-message button:last-of-type {
        background-color: #dc3545;
      }
    </style>
    <script>
      const {
        browserSupportsWebAuthn,
        startRegistration,
        startAuthentication,
      } = SimpleWebAuthnBrowser;

      document.addEventListener("DOMContentLoaded", () => {
        const token = localStorage.getItem("jwtToken");
        const formContainer = document.getElementById("form-container");
        const loggedInMessage = document.getElementById("logged-in-message");
        const registerYubikeyButton = document.getElementById(
          "register-yubikey-button"
        );
        const otpField = document.getElementById("otp-field");
        const otpRadioButton = document.getElementById("otp-radio");

        if (token) {
          formContainer.style.display = "none";
          loggedInMessage.style.display = "block";
        } else {
          otpField.style.display = "none";
          formContainer.style.display = "block";
          loggedInMessage.style.display = "none";
        }

        document.querySelectorAll('input[name="action"]').forEach((radio) => {
          radio.addEventListener("change", function () {
            if (otpRadioButton.checked) {
              otpField.style.display = "block";
            } else {
              otpField.style.display = "none";
            }
          });
        });
      });

      async function handleSubmit(event) {
        event.preventDefault();

        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;
        const action = document.querySelector(
          'input[name="action"]:checked'
        ).value;
        const otp = document.getElementById("otp").value;

        try {
          let response;
          if (action === "register") {
            response = await fetch("http://localhost:8080/register", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
              throw new Error("Failed to register user");
            }

            alert("Registration successful");
          } else if (action === "login") {
            try {
              const response = await fetch("http://localhost:8080/login", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
              });

              if (!response.ok) {
                throw new Error("Failed to login");
              }

              const responseData = await response.json();

              // Check if the response contains a token or WebAuthn options
              if (responseData.token) {
                // JWT token present, perform login
                localStorage.setItem("jwtToken", responseData.token);
                localStorage.setItem("username", username);

                document.getElementById("form-container").style.display =
                  "none";
                document.getElementById("logged-in-message").style.display =
                  "block";

                alert("Login successful");
              } else if (responseData.publicKey) {
                // WebAuthn options present, handle WebAuthn login
                const authResp = await startAuthentication(
                  responseData.publicKey
                );

                const webauthnResponse = await fetch(
                  "http://localhost:8080/login/finish",
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ username, ...authResp }),
                  }
                );

                if (!webauthnResponse.ok) {
                  throw new Error("Failed to finish WebAuthn login");
                }

                const { token } = await webauthnResponse.json();

                localStorage.setItem("jwtToken", token);
                localStorage.setItem("username", username);

                document.getElementById("form-container").style.display =
                  "none";
                document.getElementById("logged-in-message").style.display =
                  "block";

                alert("Login successful with WebAuthn");
              } else {
                throw new Error("Unexpected response format");
              }
            } catch (error) {
              console.error("Error:", error);
              alert("Login failed");
            }
          } else if (action === "otp-login") {
            console.log(otp);
            response = await fetch("http://localhost:8080/login/otp", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ username, password, otp }),
            });

            if (!response.ok) {
              throw new Error("Failed to login with OTP");
            }

            const { token } = await response.json();

            localStorage.setItem("jwtToken", token);

            document.getElementById("form-container").style.display = "none";
            document.getElementById("logged-in-message").style.display =
              "block";

            alert("Login successful with OTP");
          }
        } catch (error) {
          console.error("Error:", error);
          alert("Operation failed");
        }
      }

      async function registerYubiKey() {
        const username = localStorage.getItem("username");
        const token = localStorage.getItem("jwtToken");

        try {
          const response = await fetch(
            "http://localhost:8080/webauthn/register/start",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
            }
          );

          if (!response.ok) {
            throw new Error("Failed to initiate YubiKey registration");
          }

          const { publicKey } = await response.json();
          const credential = await startRegistration(publicKey);

          const finishResponse = await fetch(
            "http://localhost:8080/webauthn/register/finish",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify({ ...credential }),
            }
          );

          if (!finishResponse.ok) {
            throw new Error("Failed to finish YubiKey registration");
          }

          alert("YubiKey registration successful");
        } catch (error) {
          console.error("Error:", error);
          alert("Failed to register YubiKey");
        }
      }

      async function registerOTPYubiKey() {
        const token = localStorage.getItem("jwtToken");
        try {
          const response = await fetch(
            "http://localhost:8080/otp/register/start",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
            }
          );

          if (!response.ok) {
            throw new Error("Failed to initiate OTP YubiKey registration");
          }

          alert(
            (await response.text()) +
              " -   Copy TOTP secret ke Yubikey authenticator"
          );
        } catch (error) {
          console.error("Error:", error);
          alert("Failed to register OTP YubiKey");
        }
      }

      async function hitProtectedEndpoint() {
        const token = localStorage.getItem("jwtToken");

        try {
          const response = await fetch("http://localhost:8080/protected", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
            },
          });

          if (!response.ok) {
            throw new Error("Failed to access protected endpoint");
          }

          const data = await response.text();
          alert(data);
        } catch (error) {
          console.error("Error:", error);
          alert("Failed to access protected endpoint");
        }
      }

      async function hitProtectedEndpointWithWebAuthn() {
        const token = localStorage.getItem("jwtToken");

        try {
          const response = await fetch(
            "http://localhost:8080/protected/webauthn/start",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
            }
          );

          if (!response.ok) {
            throw new Error(
              "Failed to initiate WebAuthn for protected endpoint"
            );
          }

          const { publicKey } = await response.json();
          const authResp = await startAuthentication(publicKey);
          console.log(authResp);
          const webauthnResponse = await fetch(
            "http://localhost:8080/protected/webauthn/finish",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
              body: JSON.stringify(authResp),
            }
          );

          if (!webauthnResponse.ok) {
            throw new Error("Failed to finish WebAuthn authentication");
          }

          const data = await webauthnResponse.text();
          alert(data);
        } catch (error) {
          console.error("Error:", error);
          alert("Failed to access protected endpoint with WebAuthn");
        }
      }

      async function uploadFile() {
        const fileInput = document.getElementById("file-input");
        const file = fileInput.files[0];
        const token = localStorage.getItem("jwtToken");

        if (!file) {
          alert("Please select a file");
          return;
        }

        const formData = new FormData();
        formData.append("file", file);

        try {
          const response = fetch("http://localhost:8080/encrypt-file", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
            },
            body: formData,
          })
            .then((response) => {
              if (!response.ok) {
                throw new Error("Error uploading or encrypting file");
              }
              return response.blob(); // Get the response as a Blob (binary data)
            })
            .then((blob) => {
              // Create a temporary download link and trigger the download
              const url = window.URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = file.name + ".gpg"; // Name the encrypted file
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              window.URL.revokeObjectURL(url); // Clean up URL object
            });
        } catch (error) {
          console.error("Error:", error);
          alert("File upload failed");
        }
      }

      async function decryptFile() {
        const fileInput = document.getElementById("file-input-decrypt");
        const file = fileInput.files[0];
        const token = localStorage.getItem("jwtToken");

        if (!file) {
          alert("Please select a file to decrypt");
          return;
        }

        const formData = new FormData();
        formData.append("file", file);

        try {
          const response = await fetch("http://localhost:8080/decrypt-file", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
            },
            body: formData,
          });

          if (!response.ok) {
            throw new Error("Failed to decrypt file");
          }

          const blob = await response.blob();
          const downloadUrl = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = downloadUrl;
          link.download = "decrypted_file";
          document.body.appendChild(link);
          link.click();
          link.remove();

          alert("File decrypted successfully");
        } catch (error) {
          console.error("Error:", error);
          alert("File decryption failed");
        }
      }

      function logout() {
        localStorage.removeItem("jwtToken");
        document.getElementById("form-container").style.display = "block";
        document.getElementById("logged-in-message").style.display = "none";
      }

      async function hitProtectedEndpointWithOTP() {
        const token = localStorage.getItem("jwtToken");
        const otp = prompt("Enter your OTP:"); // Prompt user to enter OTP

        if (!otp) {
          alert("OTP is required");
          return;
        }

        try {
          const response = await fetch("http://localhost:8080/protected/otp", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ otp }), // Send OTP in the request body
          });

          if (!response.ok) {
            throw new Error("Failed to access protected endpoint with OTP");
          }

          const data = await response.text();
          alert(data); // Show response from the server
        } catch (error) {
          console.error("Error:", error);
          alert("Failed to access protected endpoint with OTP");
        }
      }
    </script>
  </head>

  <body>
    <div class="container">
      <h1>Login/Register</h1>
      <div id="form-container">
        <div class="toggle-action">
          <label>
            <input type="radio" name="action" value="register" checked />
            Register
          </label>
          <label>
            <input type="radio" name="action" value="login" /> Login
          </label>
          <label>
            <input
              type="radio"
              name="action"
              value="otp-login"
              id="otp-radio"
            />
            OTP Login
          </label>
        </div>
        <form onsubmit="handleSubmit(event);">
          <label for="username">Username:</label>
          <input type="text" id="username" name="username" required />
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" />
          <div class="otp-field" id="otp-field">
            <label for="otp">OTP</label>
            <input type="number" id="otp" />
          </div>
          <button type="submit">Submit</button>
        </form>
      </div>
      <div
        id="logged-in-message"
        class="logged-in-message"
        style="display: none"
      >
        <p>You are logged in!</p>
        <button id="register-yubikey-button" onclick="registerYubiKey()">
          Register MFA Webauthn Yubikey
        </button>
        <button onclick="registerOTPYubiKey()">Register OTP YubiKey</button>
        <button id="protected-button" onclick="hitProtectedEndpoint()">
          Access Protected Endpoint
        </button>
        <button
          id="protected-webauthn-button"
          onclick="hitProtectedEndpointWithWebAuthn()"
        >
          Access Protected Endpoint with WebAuthn
        </button>
        <button
          id="protected-otp-button"
          onclick="hitProtectedEndpointWithOTP()"
        >
          Access Protected Endpoint with OTP
        </button>
        <input
          type="file"
          id="file-input"
          style="display: none"
          onchange="uploadFile()"
        />
        <button onclick="document.getElementById('file-input').click()">
          Upload and Encrypt File
        </button>
        <input
          type="file"
          id="file-input-decrypt"
          style="display: none"
          onchange="decryptFile()"
        />
        <button onclick="document.getElementById('file-input-decrypt').click()">
          Upload and Decrypt File
        </button>
        <button id="logout-button" onclick="logout()">Logout</button>
      </div>
    </div>
  </body>
</html>
```
</pre>

Kode HTML di atas adalah sebuah halaman login dan registrasi yang mendukung beberapa metode otentikasi, termasuk:

- **Login/Registrasi**

1. Terdapat form untuk login atau registrasi dengan username dan password.
2. Tersedia opsi login dengan OTP (One-Time Password).
3. Berdasarkan pilihan pengguna (register/login/otp-login), tampilan form dan input menyesuaikan.

- **Integrasi dengan WebAuthn dan OTP**

1. Ada integrasi dengan WebAuthn untuk registrasi dan login menggunakan YubiKey atau perangkat otentikasi fisik lain.
2. Dukungan juga untuk login menggunakan OTP (misalnya, kode dari aplikasi autentikasi atau perangkat YubiKey).

- **Tombol-tombol Otentikasi Lanjutan**

1. Setelah login berhasil, pengguna dapat mengakses fitur tambahan:
	- Mendaftar YubiKey untuk MFA (Multi-Factor Authentication) menggunakan WebAuthn.
	- Mendaftarkan OTP di YubiKey.
	- Mengakses endpoint yang dilindungi dengan token JWT atau WebAuthn.
	
- **Fitur Enkripsi/Deskripsi File**

1. Pengguna juga dapat mengunggah file yang akan dienkripsi dan diunduh dalam format terenkripsi.
2. Ada opsi untuk mendekripsi file yang diunggah.

- **Tampilan Dinamis**

1. Berdasarkan keberadaan JWT token di localStorage, elemen login/registrasi akan disembunyikan, dan elemen pesan "You are logged in" akan ditampilkan.

Secara keseluruhan, halaman ini menyediakan antarmuka yang mendukung berbagai metode otentikasi modern (password, OTP, WebAuthn), serta fitur enkripsi dan dekripsi file untuk pengguna yang sudah terautentikasi.
