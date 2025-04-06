package models

type User struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"` // TODO: change this to receive the hash of the password
	UserType string `json:"userType" binding:"required"`
}
