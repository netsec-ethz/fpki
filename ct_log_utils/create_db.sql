DROP DATABASE IF EXISTS `google_xenon2022`;
CREATE DATABASE google_xenon2022;
CREATE USER IF NOT EXISTS 'clonetool'@localhost IDENTIFIED BY 'letmein';
GRANT ALL PRIVILEGES ON google_xenon2022.* TO 'clonetool'@localhost;
FLUSH PRIVILEGES;
