package configs

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var UserCollection *mongo.Collection

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

	UserCollection = client.Database("playground").Collection("users")
	log.Println("Mongo initialized success")
}
