CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    password TEXT,
    role VARCHAR(50) DEFAULT 'user'
);

CREATE TABLE scan_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    url TEXT,
    score INT,
    result VARCHAR(100),
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE contact_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);