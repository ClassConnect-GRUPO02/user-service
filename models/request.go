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

type TeacherNotificationSettingsRequest struct {
	PushEnabled          *bool                   `json:"pushEnabled" binding:"required"`
	EmailEnabled         *bool                   `json:"emailEnabled" binding:"required"`
	AssignmentSubmission *NotificationPreference `json:"assignmentSubmission" binding:"required"`
	StudentFeedback      *NotificationPreference `json:"studentFeedback" binding:"required"`
}

type StudentNotificationSettingsRequest struct {
	PushEnabled          *bool                   `json:"pushEnabled" binding:"required"`
	EmailEnabled         *bool                   `json:"emailEnabled" binding:"required"`
	NewAssignment        *NotificationPreference `json:"newAssignment" binding:"required"`
	DeadlineReminder     *NotificationPreference `json:"deadlineReminder" binding:"required"`
	CourseEnrollment     *NotificationPreference `json:"courseEnrollment" binding:"required"`
	FavoriteCourseUpdate *NotificationPreference `json:"favoriteCourseUpdate" binding:"required"`
	TeacherFeedback      *NotificationPreference `json:"teacherFeedback" binding:"required"`
}
