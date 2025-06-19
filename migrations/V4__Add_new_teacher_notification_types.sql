-- Write the migration queries here
ALTER TABLE teachers_notifications_settings ADD COLUMN "course_assigned" SMALLINT DEFAULT 3;
ALTER TABLE teachers_notifications_settings ADD COLUMN "course_revoked" SMALLINT DEFAULT 3;
