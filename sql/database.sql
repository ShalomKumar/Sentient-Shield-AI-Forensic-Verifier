CREATE DATABASE sentinel_db;
USE sentinel_db;

CREATE TABLE threat_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_input TEXT,
    risk_score INT,
    attack_type VARCHAR(100),
    status VARCHAR(20),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);