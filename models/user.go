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
