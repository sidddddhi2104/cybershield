CREATE DATABASE IF NOT EXISTS cyber_db;

USE cyber_db;

-- ======================================
-- USERS TABLE
-- ======================================

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200),
    email VARCHAR(200) UNIQUE,
    password VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ======================================
-- SCAN REPORTS TABLE
-- ======================================

CREATE TABLE scan_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    url TEXT,
    score INT,
    result VARCHAR(100),
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id) REFERENCES users(id)
    ON DELETE CASCADE
);

-- ======================================
-- CONTACT REPORTS TABLE
-- ======================================

CREATE TABLE contact_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200),
    email VARCHAR(200),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ======================================
-- DEFAULT ADMIN ACCOUNT
-- EMAIL: admin@cybershield.com
-- PASSWORD: admin123
-- ======================================

INSERT INTO users(name, email, password, role)
VALUES(
    'Administrator',
    'admin@cybershield.com',
    '$pbkdf2-sha256$29000$7v3fO6f0P6f0P6f0P6f0Pw$5tX9M3d8K4v0A8N3d9f1H7l2G5sK7mY8bX0N7k2A9vQ',
    'admin'
);