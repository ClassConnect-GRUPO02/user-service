CREATE DATABASE users_db;
\c users_db

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    name VARCHAR(255),
    type VARCHAR(255),
    password_hash VARCHAR(255),
    blocked_until BIGINT,
    latitude FLOAT,
    longitude FLOAT
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

INSERT INTO admins VALUES (DEFAULT, 'admin', 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997') ON CONFLICT DO NOTHING
