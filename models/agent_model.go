package models

import "go.mongodb.org/mongo-driver/v2/bson"

type CreateAgent struct {
	Id bson.ObjectID `json:"_id"`
}
