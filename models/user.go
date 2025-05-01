package models

type User struct {
	Name      string  `json:"name" binding:"required"`
	Email     string  `json:"email" binding:"required"`
	Password  string  `json:"password" binding:"required"`
	UserType  string  `json:"userType" binding:"required"`
	Latitude  float64 `json:"latitude" binding:"required"`
	Longitude float64 `json:"longitude" binding:"required"`
}

// The public information of a user does not contain its location (latitude and longitude)
type UserPublicInfo struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	UserType string `json:"userType"`
}

// The public information of a user does not contain its location (latitude and longitude)
type UserFullInfo struct {
	Id               int     `json:"id"`
	Name             string  `json:"name"`
	Email            string  `json:"email"`
	UserType         string  `json:"userType"`
	RegistrationDate string  `json:"registrationDate"`
	Latitude         float64 `json:"latitude" binding:"required"`
	Longitude        float64 `json:"longitude" binding:"required"`
	Blocked          bool    `json:"blocked"`
}

type UserInfo struct {
	Id        int     `json:"id"`
	Name      string  `json:"name"`
	Email     string  `json:"email"`
	UserType  string  `json:"userType"`
	Latitude  float64 `json:"latitude" binding:"required"`
	Longitude float64 `json:"longitude" binding:"required"`
}
