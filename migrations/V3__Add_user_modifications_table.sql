-- Write the migration queries here
CREATE TABLE IF NOT EXISTS user_modifications (
    id SERIAL PRIMARY KEY,
    affected_user INTEGER REFERENCES users (id),
    modification VARCHAR(255),
    timestamp DATE
);
