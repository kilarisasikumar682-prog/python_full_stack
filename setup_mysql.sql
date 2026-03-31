-- PyBank + LiveChat MySQL Setup
CREATE DATABASE IF NOT EXISTS bank_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE bank_db;

CREATE TABLE IF NOT EXISTS accounts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    account_holder VARCHAR(100) NOT NULL,
    phone_number VARCHAR(15) UNIQUE NOT NULL,
    pin VARCHAR(10) NOT NULL,
    account_type VARCHAR(20) NOT NULL DEFAULT 'SavingsAccount',
    balance DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    is_frozen TINYINT(1) NOT NULL DEFAULT 0,
    cibil_score INT NOT NULL DEFAULT 750,
    interest_rate DECIMAL(5,4) NOT NULL DEFAULT 0.0500,
    overdraft_limit DECIMAL(15,2) NOT NULL DEFAULT 500.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transaction_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    account_ref VARCHAR(20), log_type VARCHAR(30) NOT NULL,
    amount DECIMAL(15,2) DEFAULT 0.00, description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    session_token VARCHAR(64) UNIQUE NOT NULL,
    account_number VARCHAR(20) DEFAULT NULL,
    customer_name VARCHAR(100) NOT NULL DEFAULT 'Guest',
    status VARCHAR(20) NOT NULL DEFAULT 'bot',
    agent_id VARCHAR(50) DEFAULT NULL,
    unread_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    session_token VARCHAR(64) NOT NULL,
    sender_type VARCHAR(20) NOT NULL,
    sender_name VARCHAR(100) NOT NULL DEFAULT 'Unknown',
    message TEXT NOT NULL,
    msg_type VARCHAR(30) NOT NULL DEFAULT 'text',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS canned_responses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    shortcut VARCHAR(30) UNIQUE NOT NULL,
    response TEXT NOT NULL
);

-- ── LOAN TABLES ──
CREATE TABLE IF NOT EXISTS loan_products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    min_amount DECIMAL(15,2) NOT NULL,
    max_amount DECIMAL(15,2) NOT NULL,
    interest_rate DECIMAL(5,4) NOT NULL,
    min_tenure_months INT NOT NULL,
    max_tenure_months INT NOT NULL,
    min_cibil_score INT NOT NULL,
    description TEXT,
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS loan_applications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    application_id VARCHAR(30) UNIQUE NOT NULL,
    account_number VARCHAR(20) NOT NULL,
    loan_product_id INT NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    tenure_months INT NOT NULL,
    interest_rate DECIMAL(5,4) NOT NULL,
    emi_amount DECIMAL(15,2) NOT NULL,
    purpose TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    cibil_at_application INT NOT NULL,
    approved_by VARCHAR(50),
    approved_at TIMESTAMP,
    rejection_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS active_loans (
    id INT PRIMARY KEY AUTO_INCREMENT,
    loan_id VARCHAR(30) UNIQUE NOT NULL,
    application_id VARCHAR(30) NOT NULL,
    account_number VARCHAR(20) NOT NULL,
    principal_amount DECIMAL(15,2) NOT NULL,
    interest_rate DECIMAL(5,4) NOT NULL,
    tenure_months INT NOT NULL,
    emi_amount DECIMAL(15,2) NOT NULL,
    total_amount DECIMAL(15,2) NOT NULL,
    outstanding_balance DECIMAL(15,2) NOT NULL,
    emis_paid INT NOT NULL DEFAULT 0,
    emis_remaining INT NOT NULL,
    next_emi_date DATE,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    disbursed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS emi_payments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    payment_id VARCHAR(30) UNIQUE NOT NULL,
    loan_id VARCHAR(30) NOT NULL,
    emi_number INT NOT NULL,
    amount_paid DECIMAL(15,2) NOT NULL,
    principal_paid DECIMAL(15,2) NOT NULL,
    interest_paid DECIMAL(15,2) NOT NULL,
    outstanding_after DECIMAL(15,2) NOT NULL,
    payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'paid'
);
