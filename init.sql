CREATE DATABASE users_db;
\c users_db

CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    type VARCHAR(255),
    password VARCHAR(255)
);
