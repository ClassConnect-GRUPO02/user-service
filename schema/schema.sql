CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    name VARCHAR(255),
    type VARCHAR(255),
    password_hash VARCHAR(255),
    latitude FLOAT,
    longitude FLOAT,
    blocked_until BIGINT,
    registration_date DATE,
    activated BOOLEAN
);

CREATE TABLE IF NOT EXISTS login_attempts (
    email VARCHAR(255),
    timestamp BIGINT,
    failed_attempts SMALLINT
);

CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    name VARCHAR(255),
    password_hash VARCHAR(255)
);

INSERT INTO admins VALUES (DEFAULT, 'admin', 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS users_push_tokens (
    id INTEGER REFERENCES users (id) PRIMARY KEY,
    token VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS students_notifications_settings (
    id INTEGER REFERENCES users (id),
    push_enabled BOOLEAN,
    email_enabled BOOLEAN,
    new_assignment SMALLINT,
    deadline_reminder SMALLINT,
    course_enrollment SMALLINT,
    teacher_feedback SMALLINT,
    grading_available SMALLINT
);

CREATE TABLE IF NOT EXISTS teachers_notifications_settings (
    id INTEGER REFERENCES users (id),
    push_enabled BOOLEAN,
    email_enabled BOOLEAN,
    assignment_submission SMALLINT,
    student_feedback SMALLINT,
    course_assigned SMALLINT,
    course_revoked SMALLINT
);

CREATE TABLE IF NOT EXISTS verification_pins (
    pin BIGINT,
    email VARCHAR(255),
    expires_at BIGINT,
    consumed BOOLEAN
);

CREATE TABLE IF NOT EXISTS google_linked_emails (
    email VARCHAR(255) PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS user_modifications (
    id SERIAL PRIMARY KEY,
    affected_user INTEGER REFERENCES users (id),
    modification VARCHAR(255),
    timestamp DATE
);
