package models

import (
	"context"
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID          []byte                `bson:"_id,omitempty"`
	Name        string                `bson:"name"`
	DisplayName string                `bson:"display_name"`
	Password    string                `bson:"password"`
	Credentials []webauthn.Credential `bson:"credentials"`
}

var userCollection *mongo.Collection

func InitMongoDB() {
	clientOptions := options.Client().ApplyURI("mongodb://autopay2_log:autopay2_log@127.0.0.1:27020")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		panic(err)
	}

	userCollection = client.Database("playground").Collection("users")
	log.Println("Mongo initialized success")
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getUserByName(name string) (*User, error) {
	var user User
	err := userCollection.FindOne(context.TODO(), bson.M{"name": name}).Decode(&user)
	return &user, err
}

func saveUser(user *User) error {
	_, err := userCollection.InsertOne(context.TODO(), user)
	return err
}

func updateUser(user *User) error {
	_, err := userCollection.UpdateOne(
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

func generateUserID(name string) ([]byte, error) {
	return []byte(name), nil
}
