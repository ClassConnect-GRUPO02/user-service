package models

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthRequest struct {
	Token string `header:"Authorization" binding:"required"`
}
