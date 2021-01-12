CREATE DATABASE db_passmanager;
USE db_passmanager;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name NVARCHAR(30) NOT NULL,
    email NVARCHAR(30) NOT NULL,
    login_pass NVARCHAR(255) NOT NULL,
    login_salt NVARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS master_passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    master_pass NVARCHAR(255) NOT NULL,
    master_salt NVARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pass NVARCHAR(255),
    name NVARCHAR(255),
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name NVARCHAR(255),
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE USER 'passmanagerAdmin'@'%' IDENTIFIED WITH mysql_native_password BY 'db-78n9n';
GRANT INSERT ON db_passmanager.* TO 'passmanagerAdmin'@'%';
GRANT SELECT ON db_passmanager.* TO 'passmanagerAdmin'@'%';
GRANT UPDATE ON db_passmanager.* TO 'passmanagerAdmin'@'%';
GRANT DELETE ON db_passmanager.* TO 'passmanagerAdmin'@'%';
FLUSH PRIVILEGES;

CREATE USER 'passmanagerUser'@'%' IDENTIFIED WITH mysql_native_password BY 'db-78n9n';
GRANT INSERT ON db_passmanager.* TO 'passmanagerUser'@'%';
GRANT SELECT ON db_passmanager.* TO 'passmanagerUser'@'%';
GRANT DELETE ON db_passmanager.devices TO 'passmanagerUser'@'%';
FLUSH PRIVILEGES;