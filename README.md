# PyBank - Secure Banking System

<div align="center">

![PyBank Logo](https://img.shields.io/badge/PyBank-Banking%20System-blue)
![Security](https://img.shields.io/badge/Security-Hardened-green)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-orange)
![License](https://img.shields.io/badge/License-MIT-lightgray)

**A complete, production-ready banking system with enterprise-grade security hardening**

[Features](#features) • [Installation](#installation) • [Configuration](#configuration) • [API Reference](#api-reference) • [Security](#security)

</div>

---

## Overview

PyBank is a comprehensive banking application built with Flask, featuring secure account management, loan systems, real-time chat support, and CIBIL credit scoring. The system prioritizes security through bcrypt PIN hashing, transaction locking, SQL injection prevention, and concurrent operation safety.

**Current Version:** 1.0.0 (Secure Edition)

---

## Features

### 🏦 Core Banking Features
- **Account Management**
  - Multiple account types (Savings, Checking, Premium)
  - Account creation and profile management
  - Account freezing/unfreezing capabilities
  - Real-time balance updates
  
- **Transactions**
  - Secure deposits and withdrawals
  - P2P transfers with atomic operations
  - Transaction history and logging
  - PDF receipt generation
  - CSV export functionality

- **Loan System**
  - Loan application and management
  - Interest calculation
  - EMI scheduling
  - Loan status tracking
  - Automatic CIBIL score adjustments

- **Credit Scoring**
  - CIBIL score calculation
  - Real-time score updates
  - Score-based loan eligibility
  - Historical score tracking

### 💬 Support Features
- **Live Chat System**
  - Real-time customer support
  - Ticket management
  - Message history tracking
  - Admin response capabilities

### 📊 Admin Dashboard
- **Analytics & Reporting**
  - Real-time account statistics
  - Transaction breakdown by type, time, and patterns
  - User behavior analysis
  - Activity level categorization
  - Comprehensive data visualizations

- **Account Management**
  - User account management
  - Freeze/unfreeze controls
  - Manual balance adjustments
  - Admin actions audit trail

---

## Security Features

### 🔐 Authentication & Authorization
- **PIN Security**
  - Bcrypt hashing with 10 rounds (primary)
  - SHA256 with salt fallback (if bcrypt unavailable)
  - Constant-time comparison to prevent timing attacks
  - Secure PIN verification without plain-text storage

- **Session Management**
  - Flask session-based authentication
  - Configurable session timeout
  - Admin-level access controls
  - Role-based authorization

### 🔒 Transaction Safety
- **Concurrency Control**
  - Thread-safe transaction handling
  - Row-level locking (FOR UPDATE)
  - Transaction isolation levels (READ COMMITTED)
  - Atomic multi-account operations
  - Deadlock prevention through sorted account locking

- **Account Protection**
  - Overdraft limits for checking accounts
  - Insufficient funds validation
  - Frozen account checks
  - Amount validation and constraints

### 🛡️ Data Protection
- **SQL Injection Prevention**
  - Parameterized queries throughout
  - Input validation and sanitization
  - Prepared statement usage
  - Query builder utilities

- **Database Security**
  - Support for both MySQL and SQLite
  - Configurable isolation levels
  - Transaction rollback on errors
  - Connection pooling and cleanup

### 📝 Audit & Compliance
- **Transaction Logging**
  - Complete transaction history
  - Automatic timestamp tracking
  - Description logging for all operations
  - Amount and reference tracking

- **Admin Actions**
  - Admin activity logging
  - Changes audit trail
  - Unauthorized attempt detection
  - Alert triggering for suspicious activities

---

## Installation

### Prerequisites

- **Python 3.7+**
- **Flask 2.0+**
- **MySQL 5.7+** OR **SQLite 3**
- **pip** (Python package manager)

### Step 1: Clone or Download

```bash
# Clone the repository
git clone <repository-url>
cd pybank

# Or extract the app_secure.py file
```

### Step 2: Install Dependencies

```bash
# Install required packages
pip install flask pymysql bcrypt reportlab

# Optional: Install only Flask + SQLite (no MySQL)
pip install flask bcrypt reportlab
```

### Step 3: Set Up Database

#### Option A: Using SQLite (Recommended for Development)
```bash
# Database will be automatically created in the same directory
python app_secure.py
```

#### Option B: Using MySQL (Recommended for Production)
```bash
# Create database and user
mysql -u root -p
```

```sql
CREATE DATABASE bank_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'bank_user'@'localhost' IDENTIFIED BY 'strong_password_here';
GRANT ALL PRIVILEGES ON bank_db.* TO 'bank_user'@'localhost';
FLUSH PRIVILEGES;
```

### Step 4: Configure Environment Variables

Create a `.env` file in the project directory:

```bash
# Flask Configuration
SECRET_KEY=your-super-secret-key-change-this
ADMIN_KEY=secure-admin-password

# Database Configuration (MySQL)
DB_HOST=localhost
DB_PORT=3306
DB_USER=bank_user
DB_PASS=strong_password_here
DB_NAME=bank_db

# Flask Environment
FLASK_ENV=production
FLASK_DEBUG=0
```

Or set environment variables directly:

```bash
# Linux/Mac
export SECRET_KEY="your-secret-key"
export DB_HOST="localhost"
export DB_USER="bank_user"
export DB_PASS="password"

# Windows (Command Prompt)
set SECRET_KEY=your-secret-key
set DB_HOST=localhost
```

### Step 5: Run the Application

```bash
python app_secure.py
```

Expected output:
```
============================================================
  🏦  PyBank SECURE Edition  |  http://127.0.0.1:8443
  DB      : MYSQL or SQLITE
  Security: ✓ Bcrypt or ⚠ SHA256 fallback
  Support : https://127.0.0.1:8443/admin/support
  Admin   : https://127.0.0.1:8443/admin
============================================================
```

---

## Configuration

### Core Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `pybank-secret-2024-change-me` | Flask session encryption key |
| `DB_TYPE` | Auto-detected | `mysql` or `sqlite` |
| `DB_HOST` | `localhost` | Database server hostname |
| `DB_PORT` | `3306` | Database server port |
| `DB_USER` | `root` | Database user |
| `DB_PASS` | `Admin_451807` | Database password |
| `DB_NAME` | `bank_db` | Database name |
| `ADMIN_KEY` | `admin` | Admin authentication key |

### Database Configuration

**MySQL Connection Pool:**
- Charset: `utf8mb4`
- Isolation Level: `READ COMMITTED`
- Cursor Type: `DictCursor`

**SQLite Configuration:**
- Path: `bank_data.db` (same directory as app)
- Isolation Level: `DEFERRED`
- Row Factory: `Row` objects

---

## Usage

### Starting as a Regular User

1. Navigate to `http://127.0.0.1:8443`
2. Click "Create Account"
3. Fill in your details:
   - Account Holder Name
   - Account Type (Savings/Checking/Premium)
   - PIN (4-8 digits)
   - Initial Balance
4. Login with your Account Number and PIN

### Account Types

- **Savings Account**
  - No overdraft facility
  - Higher interest rates
  - Withdrawal restrictions may apply
  
- **Checking Account**
  - Overdraft facility up to configured limit
  - No balance restrictions
  - Ideal for frequent transactions
  
- **Premium Account**
  - Higher transaction limits
  - Dedicated support
  - Advanced features

### Admin Access

1. Navigate to `http://127.0.0.1:8443/admin`
2. Enter Admin Key (configured in environment)
3. Access admin dashboard for:
   - Account management
   - Analytics and reporting
   - Chat support review
   - System configuration

---

## API Reference

### Authentication

All endpoints (except `/admin`) require `account_number` and `pin` in session or request.

```
POST /login
Content-Type: application/x-www-form-urlencoded

account_number=ACC123456&pin=1234
```

### Account Endpoints

#### Get Account Details
```
GET /api/account/details
Response: { account_number, balance, account_holder, cibil_score, ... }
```

#### Update Profile
```
POST /api/account/update
Parameters: account_holder, email, phone
```

### Transaction Endpoints

#### Deposit
```
POST /api/transaction/deposit
Parameters: amount
Response: { success, message, new_balance }
```

#### Withdraw
```
POST /api/transaction/withdraw
Parameters: amount
Response: { success, message, new_balance }
```

#### Transfer
```
POST /api/transaction/transfer
Parameters: to_account, amount
Response: { success, message, transaction_id }
```

#### Get Statement
```
GET /api/transaction/statement
Query: ?limit=50&offset=0
Response: { transactions[], total_count }
```

#### Download Receipt (PDF)
```
GET /api/transaction/receipt/<transaction_id>
Response: PDF file
```

### Loan Endpoints

#### Apply for Loan
```
POST /api/loan/apply
Parameters: amount, loan_type, tenure_months
Response: { success, message, loan_id }
```

#### Get Loan Details
```
GET /api/loan/<loan_id>
Response: { loan_id, amount, balance, emi, status, ... }
```

#### Pay EMI
```
POST /api/loan/<loan_id>/pay_emi
Parameters: amount
Response: { success, new_balance }
```

### Chat Endpoints

#### Send Message
```
POST /api/chat/send
Parameters: message, subject
Response: { success, ticket_id }
```

#### Get Messages
```
GET /api/chat/messages
Response: { conversations[] }
```

### Admin API Endpoints

#### Dashboard Stats
```
GET /api/admin/analytics/dashboard
Response: { top_accounts, recent_activity }
```

#### Transaction Breakdown
```
GET /api/admin/analytics/transaction-breakdown
Response: { by_type[], by_hour[], by_day[], by_amount_range[] }
```

#### User Behavior
```
GET /api/admin/analytics/user-behavior
Response: { activity_levels[], recent_cibil_changes[] }
```

---

## Database Schema

### Core Tables

**accounts**
- `id` (INT, PK)
- `account_number` (VARCHAR, UNIQUE)
- `account_holder` (VARCHAR)
- `pin_hash` (VARCHAR) - Bcrypt/SHA256 hashed
- `balance` (DECIMAL)
- `account_type` (VARCHAR) - Savings/Checking/Premium
- `overdraft_limit` (DECIMAL)
- `cibil_score` (INT)
- `is_frozen` (BOOLEAN)
- `created_at`, `updated_at` (TIMESTAMP)

**loans**
- `id` (INT, PK)
- `account_ref` (VARCHAR, FK)
- `loan_amount` (DECIMAL)
- `remaining_balance` (DECIMAL)
- `emi_amount` (DECIMAL)
- `tenure_months` (INT)
- `rate_percent` (DECIMAL)
- `status` (VARCHAR) - Approved/Pending/Rejected/Closed
- `created_at`, `updated_at` (TIMESTAMP)

**transaction_log**
- `id` (INT, PK)
- `account_ref` (VARCHAR, FK)
- `log_type` (VARCHAR) - Deposit/Withdrawal/Transfer/EMI
- `amount` (DECIMAL)
- `description` (VARCHAR)
- `created_at` (TIMESTAMP)

**chat_messages**
- `id` (INT, PK)
- `account_ref` (VARCHAR, FK)
- `message` (TEXT)
- `sender_type` (VARCHAR) - User/Admin
- `created_at` (TIMESTAMP)

**admin_alerts**
- `id` (INT, PK)
- `alert_type` (VARCHAR)
- `description` (TEXT)
- `severity` (VARCHAR) - Low/Medium/High
- `created_at` (TIMESTAMP)

---

## Security Best Practices

### For Deployment

1. **Change Default Secrets**
   ```bash
   export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
   export ADMIN_KEY=$(python -c 'import secrets; print(secrets.token_hex(16))')
   ```

2. **Use Strong Database Password**
   ```bash
   export DB_PASS=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
   ```

3. **Enable HTTPS**
   - Use proper SSL certificates
   - Configure Flask with production WSGI server (Gunicorn, uWSGI)
   - Set `FLASK_ENV=production`

4. **Database Security**
   - Restrict database connections to localhost
   - Use strong authentication
   - Enable query logging for audit
   - Regular backups

5. **Application Security**
   - Keep dependencies updated: `pip install --upgrade flask pymysql bcrypt`
   - Implement rate limiting on login endpoints
   - Monitor admin access logs
   - Regular security audits

### For Development

- Never commit `.env` files to version control
- Use SQLite for local development
- Enable debug logging for troubleshooting
- Test with multiple concurrent transactions

---

## Troubleshooting

### bcrypt Not Installed

If you see:
```
[WARN] bcrypt not installed - using SHA256 fallback
```

Install bcrypt:
```bash
pip install bcrypt
```

### Database Connection Error

**MySQL Connection Failed:**
```bash
# Check MySQL is running
mysql -u root -p -e "SELECT 1;"

# Verify credentials in .env
# Verify database exists
mysql -u bank_user -p bank_db -e "SHOW TABLES;"
```

**SQLite Permission Error:**
```bash
# Ensure write permissions in app directory
chmod 755 .
ls -la bank_data.db
```

### ReportLab Not Installed

If PDF receipts are disabled:
```bash
pip install reportlab
```

### Port Already in Use

If port 8443 is occupied:
```python
# Modify the last line in app_secure.py
app.run(
    host='127.0.0.1',
    port=8444,  # Change to different port
    debug=True
)
```

---

## Performance Optimization

### Database Queries
- Use prepared statements (parameterized queries)
- Index frequently queried columns
- Monitor slow query logs

### Concurrency
- Row-level locking prevents race conditions
- Connection pooling via database driver
- Thread-safe transaction handling

### Caching
- Implement Redis for session management
- Cache account statistics
- Add query result caching

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards
- Follow PEP 8
- Add docstrings to functions
- Include security implications in comments
- Test with both MySQL and SQLite

---

## License

This project is licensed under the MIT License - see LICENSE file for details.

```
MIT License

Copyright (c) 2024 PyBank Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Support

For issues, questions, or feature requests:

- **Documentation**: Check the [API Reference](#api-reference) section
- **Bug Reports**: Create an issue with reproduction steps
- **Security Issues**: Please email security@pybank-banking.com
- **Live Chat**: Available in-app for registered users
- **Admin Support**: https://127.0.0.1:8443/admin/support

---

## Roadmap

- [ ] Two-factor authentication (2FA)
- [ ] Biometric login support
- [ ] Investment portfolio features
- [ ] Automated bill payment
- [ ] International money transfer
- [ ] Mobile app (iOS/Android)
- [ ] API rate limiting dashboard
- [ ] Advanced fraud detection

---

## Disclaimer

**PyBank is provided for educational and demonstration purposes.** While it implements security best practices, it should not be used in production without:
1. Comprehensive security audit
2. Compliance review (regulatory requirements)
3. Professional penetration testing
4. Insurance and legal consultation
5. Regular security updates

For production banking systems, consult with cybersecurity professionals and financial regulators.

---

<div align="center">

**Made with ❤️ by PyBank Team**

*Secure Banking for Everyone*

</div>
