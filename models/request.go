package models

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthRequest struct {
	Token string `header:"Authorization" binding:"required"`
}

type EditUserRequest struct {
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required"`
}

type CreateAdminRequest struct {
	Email    string `json:"email" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AddPushTokenRequest struct {
	PushToken string `json:"token" binding:"required"`
}

type NotifyUserRequest struct {
	Title string `json:"title" binding:"required"`
	Body  string `json:"body" binding:"required"`
}

type SetUserNotificationSettingsRequest struct {
	PushNotifications  bool `json:"pushNotifications" binding:"required"`
	EmailNotifications bool `json:"emailNotifications" binding:"required"`
}
