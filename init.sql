CREATE DATABASE users_db;
\c users_db

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    name VARCHAR(255),
    type VARCHAR(255),
    password_hash VARCHAR(255),
    is_blocked BOOLEAN NOT NULL,
    latitude FLOAT,
    longitude FLOAT
);
