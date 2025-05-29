CREATE DATABASE users_db;
\c users_db
\i /docker-entrypoint-initdb.d/schema.sql
