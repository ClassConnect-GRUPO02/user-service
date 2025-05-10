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

type NotificationPreference = int

const (
	Push         NotificationPreference = 1
	Email        NotificationPreference = 2
	PushAndEmail NotificationPreference = 3
)

type SetUserNotificationSettingsRequest struct {
	PushEnabled  *bool `json:"pushEnabled" binding:"required"`
	EmailEnabled *bool `json:"emailEnabled" binding:"required"`
	// Student specific preferences
	NewAssignment        *NotificationPreference `json:"newAssignment,omitempty"`
	DeadlineReminder     *NotificationPreference `json:"deadlineReminder,omitempty"`
	CourseEnrollment     *NotificationPreference `json:"courseEnrollment,omitempty"`
	FavoriteCourseUpdate *NotificationPreference `json:"favoriteCourseUpdate,omitempty"`
	TeacherFeedback      *NotificationPreference `json:"teacherFeedback,omitempty"`
	// Teacher specific preferences
	AssignmentSubmission *NotificationPreference `json:"assignmentSubmission,omitempty"`
	StudentFeedback      *NotificationPreference `json:"studentFeedback,omitempty"`
}
