-- Write the migration queries here
ALTER TABLE students_notifications_settings ADD COLUMN "grading_available" SMALLINT DEFAULT 3;
