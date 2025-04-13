package models

type User struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	UserType string `json:"userType" binding:"required"`
}

type UserInfo struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	UserType string `json:"userType"`
}
