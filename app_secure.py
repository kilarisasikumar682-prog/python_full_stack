
"""
PyBank - Complete Banking System with Security Hardening
Features: Banking, Loans, Live Chat, CIBIL Scoring
Security: Bcrypt PIN hashing, Transaction locking, SQL injection prevention
"""
import os
import random
import re
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager
from threading import Lock
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, send_file)
from io import BytesIO
import csv
import io

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    PDF_ENABLED = True
except ImportError:
    PDF_ENABLED = False
    print("[WARN] ReportLab not available - PDF receipts disabled")

try:
    import pymysql
    import pymysql.cursors
    DB_TYPE = "mysql"
except ImportError:
    import sqlite3
    DB_TYPE = "sqlite"

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("[WARN] bcrypt not installed - using SHA256 fallback")
    print("      Install: pip install bcrypt")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "pybank-secret-2024-change-me")

MYSQL_CONFIG = {
    "host":     os.environ.get("DB_HOST",     "localhost"),
    "port":     int(os.environ.get("DB_PORT", 3306)),
    "user":     os.environ.get("DB_USER",     "root"),
    "password": os.environ.get("DB_PASS",     "Admin_451807"),
    "database": os.environ.get("DB_NAME",     "bank_db"),
    "charset":  "utf8mb4",
}
SQLITE_PATH = os.path.join(os.path.dirname(__file__), "bank_data.db")
ADMIN_KEY   = os.environ.get("ADMIN_KEY", "admin")

_sqlite_lock = Lock()

@contextmanager
def get_db_transaction(isolation_level='READ COMMITTED'):
    """
    Thread-safe database transaction with row locking.
    Prevents race conditions in concurrent withdrawals/transfers.
    """
    if DB_TYPE == "mysql":
        conn = pymysql.connect(**MYSQL_CONFIG, cursorclass=pymysql.cursors.DictCursor)
        conn.autocommit = False
        cur = conn.cursor()
        try:
            cur.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation_level}")
            yield conn, cur
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cur.close()
            conn.close()
    else:  # SQLite
        with _sqlite_lock:
            conn = sqlite3.connect(SQLITE_PATH, isolation_level='DEFERRED')
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
                yield conn, cur
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                cur.close()
                conn.close()

def q(sql, params=(), fetch="all", commit=False):
    """
    Legacy query function - maintained for backward compatibility.
    Use q_safe() for reads and get_db_transaction() for writes.
    """
    if commit:
        with get_db_transaction() as (conn, cur):
            if DB_TYPE == "sqlite":
                sql = sql.replace("%s", "?")
            cur.execute(sql, params)
            if fetch == "lastrowid":
                return cur.lastrowid
            return None
    else:
        # Read operation
        return q_safe(sql, params, fetch)


def q_safe(sql, params=(), fetch="all"):
    """Read-only query with SQL injection protection."""
    if DB_TYPE == "mysql":
        conn = pymysql.connect(**MYSQL_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    else:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        sql = sql.replace("%s", "?")

    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        if fetch == "all":
            rows = cur.fetchall()
            return [dict(r) for r in rows]
        elif fetch == "one":
            row = cur.fetchone()
            return dict(row) if row else None
        return None
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════
#  PIN SECURITY - BCRYPT HASHING
# ═══════════════════════════════════════════════════════════════

def hash_pin(pin: str) -> str:
    """Securely hash a PIN using bcrypt or SHA256 fallback."""
    if BCRYPT_AVAILABLE:
        return bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt(rounds=10)).decode('utf-8')
    else:
        # SHA256 fallback with salt
        salt = os.urandom(32).hex()
        hashed = hashlib.sha256((pin + salt).encode('utf-8')).hexdigest()
        return f"sha256${salt}${hashed}"


def verify_pin(pin: str, hashed: str) -> bool:
    """Verify PIN against hash. Constant-time to prevent timing attacks."""
    if BCRYPT_AVAILABLE:
        try:
            return bcrypt.checkpw(pin.encode('utf-8'), hashed.encode('utf-8'))
        except:
            pass

    # SHA256 fallback
    if hashed.startswith("sha256$"):
        try:
            import hmac
            _, salt, stored_hash = hashed.split('$')
            computed = hashlib.sha256((pin + salt).encode('utf-8')).hexdigest()
            return hmac.compare_digest(computed, stored_hash)
        except:
            return False

    # Legacy plain text (migration mode)
    return pin == hashed


# ═══════════════════════════════════════════════════════════════
#  SECURE TRANSACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def secure_withdraw(account_number: str, amount: float) -> tuple:
    """Thread-safe withdrawal with row locking."""
    try:
        with get_db_transaction() as (conn, cur):
            # Lock row for update
            if DB_TYPE == "mysql":
                cur.execute("""
                    SELECT balance, account_type, overdraft_limit, is_frozen
                    FROM accounts WHERE account_number=%s FOR UPDATE
                """, (account_number,))
            else:
                cur.execute("""
                    SELECT balance, account_type, overdraft_limit, is_frozen
                    FROM accounts WHERE account_number=?
                """, (account_number,))

            acc = cur.fetchone()
            if not acc:
                return False, "Account not found"

            acc = dict(acc)

            if acc["is_frozen"]:
                return False, "Account is frozen"

            if amount <= 0:
                return False, "Amount must be positive"

            overdraft = float(acc["overdraft_limit"]) if acc["account_type"] == "CheckingAccount" else 0
            if float(acc["balance"]) - amount < -overdraft:
                msg = "Insufficient funds" if acc["account_type"] == "SavingsAccount" else "Overdraft limit reached"
                return False, msg

            new_balance = float(acc["balance"]) - amount
            if DB_TYPE == "mysql":
                cur.execute("UPDATE accounts SET balance=%s WHERE account_number=%s",
                           (new_balance, account_number))
            else:
                cur.execute("UPDATE accounts SET balance=? WHERE account_number=?",
                           (new_balance, account_number))

            return True, "Success"
    except Exception as e:
        return False, f"Transaction failed: {str(e)}"


def secure_transfer(from_acc: str, to_acc: str, amount: float) -> tuple:
    """Atomic P2P transfer with both accounts locked."""
    try:
        with get_db_transaction() as (conn, cur):
            # Lock both accounts in sorted order (prevent deadlock)
            acc_nums = sorted([from_acc, to_acc])

            if DB_TYPE == "mysql":
                cur.execute("""
                    SELECT account_number, balance, account_type, overdraft_limit, is_frozen
                    FROM accounts WHERE account_number IN (%s, %s)
                    ORDER BY account_number FOR UPDATE
                """, tuple(acc_nums))
            else:
                cur.execute("""
                    SELECT account_number, balance, account_type, overdraft_limit, is_frozen
                    FROM accounts WHERE account_number IN (?, ?)
                    ORDER BY account_number
                """, tuple(acc_nums))

            accounts = {dict(row)["account_number"]: dict(row) for row in cur.fetchall()}

            if len(accounts) != 2:
                return False, "One or both accounts not found"

            sender = accounts[from_acc]
            receiver = accounts[to_acc]

            if sender["is_frozen"] or receiver["is_frozen"]:
                return False, "Account frozen"

            if amount <= 0:
                return False, "Amount must be positive"

            overdraft = float(sender["overdraft_limit"]) if sender["account_type"] == "CheckingAccount" else 0
            if float(sender["balance"]) - amount < -overdraft:
                return False, "Insufficient funds"

            new_sender_bal = float(sender["balance"]) - amount
            new_receiver_bal = float(receiver["balance"]) + amount

            if DB_TYPE == "mysql":
                cur.execute("UPDATE accounts SET balance=%s WHERE account_number=%s",
                           (new_sender_bal, from_acc))
                cur.execute("UPDATE accounts SET balance=%s WHERE account_number=%s",
                           (new_receiver_bal, to_acc))
            else:
                cur.execute("UPDATE accounts SET balance=? WHERE account_number=?",
                           (new_sender_bal, from_acc))
                cur.execute("UPDATE accounts SET balance=? WHERE account_number=?",
                           (new_receiver_bal, to_acc))

            return True, "Transfer successful"
    except Exception as e:
        return False, f"Transfer failed: {str(e)}"

def init_db():
    conn, db = get_conn()
    cur = conn.cursor()
    ai = "AUTO_INCREMENT" if db == "mysql" else "AUTOINCREMENT"
    pk = f"INT PRIMARY KEY {ai}" if db == "mysql" else "INTEGER PRIMARY KEY AUTOINCREMENT"

    cur.execute(f"""CREATE TABLE IF NOT EXISTS accounts (
        id {pk}, account_number VARCHAR(20) UNIQUE NOT NULL,
        account_holder VARCHAR(100) NOT NULL, phone_number VARCHAR(15) UNIQUE NOT NULL,
        pin VARCHAR(255) NOT NULL, account_type VARCHAR(20) NOT NULL DEFAULT 'SavingsAccount',
        balance DECIMAL(15,2) NOT NULL DEFAULT 0.00, is_frozen TINYINT(1) NOT NULL DEFAULT 0,
        cibil_score INT NOT NULL DEFAULT 750, interest_rate DECIMAL(5,4) NOT NULL DEFAULT 0.0500,
        overdraft_limit DECIMAL(15,2) NOT NULL DEFAULT 500.00,
        failed_login_attempts INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS transaction_log (
        id {pk}, account_ref VARCHAR(20), log_type VARCHAR(30) NOT NULL,
        amount DECIMAL(15,2) DEFAULT 0.00, description TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS chat_sessions (
        id {pk}, session_token VARCHAR(64) UNIQUE NOT NULL,
        account_number VARCHAR(20) DEFAULT NULL, customer_name VARCHAR(100) NOT NULL DEFAULT 'Guest',
        status VARCHAR(20) NOT NULL DEFAULT 'bot', agent_id VARCHAR(50) DEFAULT NULL,
        unread_count INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS chat_messages (
        id {pk}, session_token VARCHAR(64) NOT NULL,
        sender_type VARCHAR(20) NOT NULL, sender_name VARCHAR(100) NOT NULL DEFAULT 'Unknown',
        message TEXT NOT NULL, msg_type VARCHAR(30) NOT NULL DEFAULT 'text',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS canned_responses (
        id {pk}, shortcut VARCHAR(30) UNIQUE NOT NULL, response TEXT NOT NULL)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS loan_products (
        id {pk}, name VARCHAR(100) NOT NULL,
        min_amount DECIMAL(15,2) NOT NULL, max_amount DECIMAL(15,2) NOT NULL,
        interest_rate DECIMAL(5,4) NOT NULL, min_tenure_months INT NOT NULL,
        max_tenure_months INT NOT NULL, min_cibil_score INT NOT NULL,
        description TEXT, active TINYINT(1) NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS loan_applications (
        id {pk}, application_id VARCHAR(30) UNIQUE NOT NULL,
        account_number VARCHAR(20) NOT NULL, loan_product_id INT NOT NULL,
        amount DECIMAL(15,2) NOT NULL, tenure_months INT NOT NULL,
        interest_rate DECIMAL(5,4) NOT NULL, emi_amount DECIMAL(15,2) NOT NULL,
        purpose TEXT, status VARCHAR(20) NOT NULL DEFAULT 'pending',
        cibil_at_application INT NOT NULL, approved_by VARCHAR(50),
        approved_at TIMESTAMP, rejection_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS active_loans (
        id {pk}, loan_id VARCHAR(30) UNIQUE NOT NULL,
        application_id VARCHAR(30) NOT NULL, account_number VARCHAR(20) NOT NULL,
        principal_amount DECIMAL(15,2) NOT NULL, interest_rate DECIMAL(5,4) NOT NULL,
        tenure_months INT NOT NULL, emi_amount DECIMAL(15,2) NOT NULL,
        total_amount DECIMAL(15,2) NOT NULL, outstanding_balance DECIMAL(15,2) NOT NULL,
        emis_paid INT NOT NULL DEFAULT 0, emis_remaining INT NOT NULL,
        next_emi_date DATE, status VARCHAR(20) NOT NULL DEFAULT 'active',
        disbursed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS emi_payments (
        id {pk}, payment_id VARCHAR(30) UNIQUE NOT NULL, loan_id VARCHAR(30) NOT NULL,
        emi_number INT NOT NULL, amount_paid DECIMAL(15,2) NOT NULL,
        principal_paid DECIMAL(15,2) NOT NULL, interest_paid DECIMAL(15,2) NOT NULL,
        outstanding_after DECIMAL(15,2) NOT NULL,
        payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(20) NOT NULL DEFAULT 'paid')""")

    cur.execute(f"""CREATE TABLE IF NOT EXISTS deposit_requests (
        id {pk},
        request_id VARCHAR(30) UNIQUE NOT NULL,
        account_number VARCHAR(20) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        reason TEXT,
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_by VARCHAR(50),
        processed_at TIMESTAMP,
        rejection_reason TEXT,
        payment_proof VARCHAR(255)
    )""")

    conn.commit()
    conn.close()
    _seed_canned()
    _seed_loan_products()
    print(f"[DB] Initialised ({db.upper()})")


def get_conn():
    if DB_TYPE == "mysql":
        try:
            return pymysql.connect(**MYSQL_CONFIG), "mysql"
        except Exception as e:
            print(f"[WARN] MySQL failed ({e}), using SQLite.")
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"


def _seed_canned():
    defaults = [
        ("balance",   "Your current balance is visible on your dashboard. Navigate to Dashboard > Available Balance."),
        ("transfer",  "To send money: Dashboard > Transfer, enter recipient's 10-digit phone, verify, then enter amount."),
        ("cibil",     "CIBIL score ranges 300-900. Deposits add +5 pts, withdrawals deduct -10 pts."),
        ("frozen",    "If your account is frozen, contact your branch admin to unfreeze."),
        ("interest",  "Savings accounts earn 5% interest per annum, applied by admin periodically."),
        ("pin",       "To reset PIN: Login page > Forgot PIN. You'll need account number, full name, and registered phone."),
        ("overdraft", "Checking accounts have a $500 overdraft limit."),
        ("close",     "To close your account: Dashboard > Close Account. Balance must be $0 first."),
        ("hours",     "PyBank support is available 24/7 via chat."),
        ("resolved",  "I'm glad I could help! Anything else?"),
        ("loans",     "Check our Loans section! Rates based on your CIBIL score. Higher score = lower interest!"),
    ]
    for shortcut, response in defaults:
        if not q_safe("SELECT 1 FROM canned_responses WHERE shortcut=%s", (shortcut,), fetch="one"):
            q("INSERT INTO canned_responses(shortcut,response) VALUES(%s,%s)",
              (shortcut, response), fetch=None, commit=True)


def _seed_loan_products():
    products = [
        ("Personal Loan - Premium", 5000, 100000, 0.0899, 6, 60, 750,
         "Low-interest personal loan for excellent credit holders."),
        ("Personal Loan - Standard", 5000, 75000, 0.1199, 6, 48, 650,
         "Flexible personal loan for good credit scores."),
        ("Personal Loan - Basic", 2000, 40000, 0.1599, 6, 36, 550,
         "Accessible personal loan for fair credit."),
        ("Home Loan - Elite", 100000, 5000000, 0.0749, 60, 360, 780,
         "Ultra-low interest home loan for top-tier borrowers."),
        ("Home Loan - Standard", 75000, 3000000, 0.0899, 60, 300, 700,
         "Competitive home loan rates for qualified buyers."),
        ("Education Loan", 10000, 500000, 0.0699, 12, 84, 600,
         "Invest in your future! Special student rates."),
        ("Business Loan - Growth", 25000, 1000000, 0.1099, 12, 84, 720,
         "Fuel your business expansion."),
        ("Business Loan - Startup", 10000, 250000, 0.1399, 12, 60, 650,
         "Launch your startup!"),
        ("Auto Loan - New Vehicle", 20000, 750000, 0.0849, 12, 84, 680,
         "Drive away in your dream car!"),
        ("Emergency Loan", 1000, 25000, 0.1799, 3, 24, 500,
         "Quick cash when you need it most."),
    ]

    for name, min_amt, max_amt, rate, min_ten, max_ten, min_cibil, desc in products:
        if not q_safe("SELECT 1 FROM loan_products WHERE name=%s", (name,), fetch="one"):
            q("""INSERT INTO loan_products(name,min_amount,max_amount,interest_rate,
                min_tenure_months,max_tenure_months,min_cibil_score,description,active)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,1)""",
              (name, min_amt, max_amt, rate, min_ten, max_ten, min_cibil, desc),
              fetch=None, commit=True)


def gen_acc_num():
    while True:
        n = str(random.randint(100000000000, 999999999999))
        if not q_safe("SELECT 1 FROM accounts WHERE account_number=%s", (n,), fetch="one"):
            return n


def update_cibil(acc_num, pts):
    acc = q_safe("SELECT cibil_score FROM accounts WHERE account_number=%s", (acc_num,), fetch="one")
    if acc:
        score = max(300, min(900, acc["cibil_score"] + pts))
        q("UPDATE accounts SET cibil_score=%s WHERE account_number=%s",
          (score, acc_num), fetch=None, commit=True)


def log_tx(acc_ref, log_type, amount, desc):
    q("INSERT INTO transaction_log(account_ref,log_type,amount,description) VALUES(%s,%s,%s,%s)",
      (acc_ref, log_type, amount, desc), fetch=None, commit=True)


def fmt_acc(n):
    return " ".join(n[i:i+4] for i in range(0, len(n), 4))


def get_account(acc_num):
    return q_safe("SELECT * FROM accounts WHERE account_number=%s", (acc_num,), fetch="one")


def calculate_emi(principal, annual_rate, months):
    if months == 0:
        return 0
    monthly_rate = annual_rate / 12
    if monthly_rate == 0:
        return principal / months
    emi = principal * monthly_rate * ((1 + monthly_rate) ** months) / (((1 + monthly_rate) ** months) - 1)
    return round(emi, 2)


def gen_loan_id(prefix="LN"):
    import time
    timestamp = int(time.time() * 1000) % 1000000
    rand = random.randint(100, 999)
    return f"{prefix}{timestamp}{rand}"


def get_cibil_discount(cibil_score):
    if cibil_score >= 850:   return 0.035
    if cibil_score >= 800:   return 0.025
    if cibil_score >= 750:   return 0.015
    if cibil_score >= 700:   return 0.008
    if cibil_score >= 650:   return 0.003
    return 0


def check_loan_eligibility(acc, product, amount, tenure):
    cibil = acc["cibil_score"]

    if cibil < product["min_cibil_score"]:
        return False, f"CIBIL score too low. Need {product['min_cibil_score']}+, you have {cibil}.", None
    if amount < product["min_amount"]:
        return False, f"Minimum loan amount is ${product['min_amount']:,.0f}.", None
    if amount > product["max_amount"]:
        return False, f"Maximum loan amount is ${product['max_amount']:,.0f}.", None
    if tenure < product["min_tenure_months"]:
        return False, f"Minimum tenure is {product['min_tenure_months']} months.", None
    if tenure > product["max_tenure_months"]:
        return False, f"Maximum tenure is {product['max_tenure_months']} months.", None
    if acc["is_frozen"]:
        return False, "Your account is frozen. Contact support.", None

    active_count = len(q_safe("SELECT 1 FROM active_loans WHERE account_number=%s AND status='active'",
                         (acc["account_number"],), fetch="all") or [])
    if active_count >= 3:
        return False, "Maximum 3 active loans allowed.", None

    base_rate = float(product["interest_rate"])
    discount = get_cibil_discount(cibil)
    adjusted_rate = max(0.05, base_rate - discount)

    return True, "You're eligible!", adjusted_rate

def calculate_cibil_by_percentage(amount: float, current_balance: float, transaction_type: str) -> int:
    """
    Calculate CIBIL score change based on percentage of current balance

    Deposit Tiers (% of balance):
    - 100%+:    +25 points (doubling or more!)
    - 50-99%:   +20 points (major deposit)
    - 25-49%:   +15 points (significant deposit)
    - 10-24%:   +10 points (good deposit)
    - 5-9%:     +7 points (decent deposit)
    - 1-4%:     +5 points (small deposit)
    - <1%:      +3 points (minimal deposit)

    Withdraw Tiers (% of balance):
    - 75%+:     -30 points (draining account!)
    - 50-74%:   -25 points (major withdrawal)
    - 25-49%:   -20 points (significant withdrawal)
    - 10-24%:   -15 points (moderate withdrawal)
    - 5-9%:     -10 points (small withdrawal)
    - 1-4%:     -7 points (minimal withdrawal)
    - <1%:      -5 points (tiny withdrawal)

    Special Cases:
    - Balance = $0: Deposit gets base +10 (starting fresh)
    - Balance < $10: Reduced penalties
    """

    # Handle edge cases
    if current_balance <= 0:
        # Starting from zero or negative
        if transaction_type == "DEPOSIT":
            return 10  # Base reward for first deposit
        else:
            return 0  # No penalty if no balance

    if amount <= 0:
        return 0

    # Calculate percentage
    percentage = (amount / current_balance) * 100

    # ========== DEPOSIT REWARDS ==========
    if transaction_type == "DEPOSIT":
        if percentage >= 100:
            return 25
        elif percentage >= 50:
            return 20
        elif percentage >= 25:
            return 15
        elif percentage >= 10:
            return 10
        elif percentage >= 5:
            return 7
        elif percentage >= 1:
            return 5
        else:
            return 3

    # ========== WITHDRAWAL PENALTIES ==========
    elif transaction_type == "WITHDRAW":
        penalty_multiplier = 1.0
        if current_balance < 100:
            penalty_multiplier = 0.5
        elif current_balance < 500:
            penalty_multiplier = 0.7

        if percentage >= 75:
            return int(-30 * penalty_multiplier)
        elif percentage >= 50:
            return int(-25 * penalty_multiplier)
        elif percentage >= 25:
            return int(-20 * penalty_multiplier)
        elif percentage >= 10:
            return int(-15 * penalty_multiplier)
        elif percentage >= 5:
            return int(-10 * penalty_multiplier)
        elif percentage >= 1:
            return int(-7 * penalty_multiplier)
        else:
            return int(-5 * penalty_multiplier)

    # ========== TRANSFER OUT PENALTIES ==========
    elif transaction_type == "TRANSFER_OUT":
        if percentage >= 50:
            return -15
        elif percentage >= 25:
            return -12
        elif percentage >= 10:
            return -8
        elif percentage >= 5:
            return -5
        else:
            return -3

    # ========== TRANSFER IN REWARDS ==========
    elif transaction_type == "TRANSFER_IN":
        if percentage >= 100:
            return 15
        elif percentage >= 50:
            return 12
        elif percentage >= 25:
            return 10
        elif percentage >= 10:
            return 7
        elif percentage >= 5:
            return 5
        else:
            return 3

    return 0


# ═══════════════════════════════════════════════════════════════
#  CHAT HELPERS
# ═══════════════════════════════════════════════════════════════

BOT_NAME = "PyBot"

BOT_RULES = [
    (r"\b(hi|hello|hey|good\s*(morning|afternoon|evening)|howdy|sup)\b",
     "Hello! 👋 I'm **PyBot**, your PyBank virtual assistant.\n\nI can help you with:\n"
     "• 💰 Balance & transactions\n• 📲 Money transfers\n• 📊 CIBIL score\n"
     "• 🔐 PIN reset\n• 🏦 Account types\n\nOr type **agent** to connect with a human."),
    (r"\b(balance|how much|my money|funds|available)\b",
     "💰 **Balance Inquiry**\n\nYour balance is shown on the **Dashboard** at the top right."),
    (r"\b(transfer|send money|send funds|p2p|payment|remit)\b",
     "📲 **How to Transfer Money**\n\n1. Go to **Dashboard → Transfer**\n"
     "2. Enter recipient's **10-digit phone number**\n3. Click **Verify**\n"
     "4. Enter amount and confirm\n\n⚡ Transfers are instant!"),
    (r"\b(cibil|credit score|credit rating|score|creditworthiness)\b",
     "📊 **CIBIL Score Guide**\n\n• **750–900** → Excellent\n"
     "• **600–749** → Good\n• **300–599** → Needs improvement"),
    (r"\b(frozen|freeze|blocked|suspended|locked|restricted)\b",
     "❄️ **Frozen Account**\n\nAll transactions are suspended when frozen.\n\n"
     "**To resolve:** Contact the bank admin."),
    (r"\b(human|agent|person|staff|representative|speak\s*to|talk\s*to|real\s*person|escalate)\b",
     "🎧 **Connecting to a Human Agent...**\n\nI'm escalating your chat now.\n\n"
     "⏱️ Expected wait: **2-5 minutes**"),
]


def bot_reply(message: str, acc_num: str = None):
    msg = message.lower().strip()
    escalate_pats = [r"\b(human|agent|person|staff|representative|speak\s*to|talk\s*to|real\s*person|escalate)\b"]
    for pat in escalate_pats:
        if re.search(pat, msg):
            return "🎧 **Connecting you to a live agent...**", True
    for pattern, reply in BOT_RULES:
        if re.search(pattern, msg):
            if acc_num and re.search(r"\bbalance\b", pattern):
                acc = get_account(acc_num)
                if acc:
                    reply = f"💰 **Your current balance: ${float(acc['balance']):,.2f}**\n\n" + reply
            return reply, False
    return ("I'm not sure about that. 🤔 Type keywords like: **balance**, **transfer**, **cibil**, **pin**, **agent**", False)


def gen_token():
    return secrets.token_hex(16)


def get_or_create_chat(acc_num=None, name="Guest"):
    token = session.get("chat_token")
    if token:
        cs = q_safe("SELECT * FROM chat_sessions WHERE session_token=%s", (token,), fetch="one")
        if cs:
            return cs
    token = gen_token()
    session["chat_token"] = token
    q("INSERT INTO chat_sessions(session_token,account_number,customer_name,status) VALUES(%s,%s,%s,'bot')",
      (token, acc_num, name), fetch=None, commit=True)
    save_msg(token, "bot", BOT_NAME,
             f"👋 Welcome to **PyBank Support**!\n\nI'm **PyBot**. How can I help you today?", "text")
    return q_safe("SELECT * FROM chat_sessions WHERE session_token=%s", (token,), fetch="one")


def save_msg(token, sender_type, sender_name, message, msg_type="text"):
    q("INSERT INTO chat_messages(session_token,sender_type,sender_name,message,msg_type) VALUES(%s,%s,%s,%s,%s)",
      (token, sender_type, sender_name, message, msg_type), fetch=None, commit=True)
    if sender_type == "customer":
        q("UPDATE chat_sessions SET updated_at=CURRENT_TIMESTAMP, unread_count=unread_count+1 WHERE session_token=%s",
          (token,), fetch=None, commit=True)
    else:
        q("UPDATE chat_sessions SET updated_at=CURRENT_TIMESTAMP WHERE session_token=%s",
          (token,), fetch=None, commit=True)


# ═══════════════════════════════════════════════════════════════
#  AUTH DECORATORS
# ═══════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "acc_num" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access required.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapped


# ═══════════════════════════════════════════════════════════════
#  PAGE ROUTES — BANKING
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        phone = request.form.get("phone","").strip()
        pin = request.form.get("pin","").strip()
        pin2 = request.form.get("pin2","").strip()
        acc_type = request.form.get("account_type","SavingsAccount")

        errors = []
        if not name or not name.replace(" ","").isalpha():
            errors.append("Name must contain letters only.")
        if len(phone)!=10 or not phone.isdigit() or phone[0]=="0":
            errors.append("Phone must be 10 digits, not starting with 0.")
        if len(pin)!=4 or not pin.isdigit():
            errors.append("PIN must be exactly 4 digits.")
        if pin!=pin2:
            errors.append("PINs do not match.")
        if q_safe("SELECT 1 FROM accounts WHERE phone_number=%s",(phone,),fetch="one"):
            errors.append("Phone already registered.")

        if errors:
            for e in errors: flash(e,"error")
            return render_template("register.html",form=request.form)

        # SECURITY: Hash PIN before storing
        pin_hashed = hash_pin(pin)

        acc_num = gen_acc_num()
        cibil = 500
        q("INSERT INTO accounts(account_number,account_holder,phone_number,pin,account_type,balance,cibil_score) VALUES(%s,%s,%s,%s,%s,0.00,%s)",
          (acc_num,name,phone,pin_hashed,acc_type,cibil),fetch=None,commit=True)
        log_tx(acc_num,"ACCOUNT_CREATED",0,f"Account opened for {name}")
        session['new_account_number'] = acc_num
        flash(f"✅ Account created successfully!","success")
        return redirect(url_for("login"))

    return render_template("register.html",form={})


@app.route("/login", methods=["GET","POST"])
def login():
    # Get new account number from session (if just registered)
    new_account = session.pop("new_account_number", None)
    formatted_account = fmt_acc(new_account) if new_account else None

    if request.method == "POST":
        raw = request.form.get("account_number","").replace(" ","").strip()
        pin = request.form.get("pin","").strip()

        acc = get_account(raw)
        if not acc:
            flash("Account not found.","error")
            return render_template("login.html", new_account=formatted_account)

        # SECURITY: Verify hashed PIN
        if not verify_pin(pin, acc["pin"]):
            flash("Incorrect PIN.","error")
            return render_template("login.html", new_account=formatted_account)

        session["acc_num"] = raw
        session["acc_name"] = acc["account_holder"]
        session["acc_type"] = acc["account_type"]
        flash(f"Welcome back, {acc['account_holder'].split()[0]}!","success")
        return redirect(url_for("dashboard"))
    return render_template("login.html", new_account=formatted_account)

@app.route("/logout")
def logout():
    name = session.get("acc_name","")
    token = session.get("chat_token")
    if token:
        q("UPDATE chat_sessions SET status='closed' WHERE session_token=%s",(token,),fetch=None,commit=True)
    session.clear()
    flash(f"Goodbye, {name.split()[0] if name else 'you'}! See you soon.","info")
    return redirect(url_for("landing"))


@app.route("/forgot-pin", methods=["GET","POST"])
def forgot_pin():
    if request.method == "POST":
        raw = request.form.get("account_number","").replace(" ","").strip()
        name = request.form.get("name","").strip()
        phone = request.form.get("phone","").strip()
        newpin = request.form.get("new_pin","").strip()
        pin2 = request.form.get("new_pin2","").strip()

        acc = get_account(raw)
        if not acc:
            flash("Account not found.","error")
            return render_template("forgot_pin.html")

        if name.lower()!=acc["account_holder"].lower() or phone!=acc["phone_number"]:
            log_tx(raw,"SECURITY_ALERT",0,f"Failed PIN reset for {raw}")
            flash("Verification failed.","error")
            return render_template("forgot_pin.html")

        if len(newpin)!=4 or not newpin.isdigit():
            flash("New PIN must be 4 digits.","error")
            return render_template("forgot_pin.html")
        if newpin!=pin2:
            flash("PINs do not match.","error")
            return render_template("forgot_pin.html")

        # SECURITY: Hash new PIN
        newpin_hashed = hash_pin(newpin)

        q("UPDATE accounts SET pin=%s WHERE account_number=%s",(newpin_hashed,raw),fetch=None,commit=True)
        log_tx(raw,"PIN_RESET",0,f"PIN reset for {raw}")
        flash("PIN reset successfully!","success")
        return redirect(url_for("login"))

    return render_template("forgot_pin.html")


@app.route("/dashboard")
@login_required
def dashboard():
    acc = get_account(session["acc_num"])
    txns = q_safe("""SELECT log_type,amount,description,created_at FROM transaction_log
                WHERE account_ref=%s ORDER BY created_at DESC LIMIT 8""", (session["acc_num"],), fetch="all")

    # Get summary stats for dashboard
    stats = q_safe("""
        SELECT
            COUNT(*) as total_txns,
            COALESCE(SUM(CASE WHEN log_type IN ('DEPOSIT','DEPOSIT_APPROVED','TRANSFER_IN') THEN amount ELSE 0 END), 0) as total_inflows,
            COALESCE(SUM(CASE WHEN log_type IN ('WITHDRAW','TRANSFER_OUT') THEN amount ELSE 0 END), 0) as total_outflows
        FROM transaction_log
        WHERE account_ref=%s
    """, (session["acc_num"],), fetch="one")

    # Get active loans count
    active_loans = q_safe("""
        SELECT COUNT(*) as count FROM active_loans
        WHERE account_number=%s AND status='active'
    """, (session["acc_num"],), fetch="one")

    return render_template("dashboard.html",
                          acc=acc,
                          txns=txns,
                          stats=stats,
                          active_loans=active_loans,
                          fmt_acc=fmt_acc)

#deposit route
@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """
    Users can no longer deposit directly.
    They must raise a deposit request ticket for admin approval.
    """
    if request.method == "POST":
        try:
            amount = float(request.form["amount"])
        except (ValueError, KeyError):
            flash("Invalid amount.", "error")
            return redirect(url_for("deposit"))

        # Validation: Amount limits
        if amount <= 0:
            flash("Amount must be positive.", "error")
            return redirect(url_for("deposit"))

        # NEW: Maximum deposit limit per transaction
        if amount > 100000:
            flash("❌ Maximum deposit amount is $100,000 per request.", "error")
            return redirect(url_for("deposit"))

        # Validate decimal places
        if round(amount, 2) != amount:
            flash("Amount can have maximum 2 decimal places.", "error")
            return redirect(url_for("deposit"))

        # Get reason (optional but recommended)
        reason = request.form.get("reason", "").strip()

        # Check account status
        acc = get_account(session["acc_num"])
        if acc["is_frozen"]:
            flash("Account is frozen. Cannot raise deposit request.", "error")
            return redirect(url_for("deposit"))

        # Generate request ID
        request_id = gen_loan_id("DEP")  # DEP123456789

        # Create deposit request
        q("""INSERT INTO deposit_requests(request_id, account_number, amount, reason, status)
             VALUES(%s, %s, %s, %s, 'pending')""",
          (request_id, session["acc_num"], amount, reason),
          fetch=None, commit=True)

        # Log the request
        log_tx(session["acc_num"], "DEPOSIT_REQUESTED", amount,
               f"Deposit request raised: {request_id} for ${amount:,.2f}")

        flash(f"✅ Deposit request submitted! Request ID: {request_id} | Amount: ${amount:,.2f} | "
              f"Status: Pending Admin Approval", "success")

        return redirect(url_for("my_deposit_requests"))

    # GET: Show deposit request form
    return render_template("deposit.html")


@app.route("/my-deposit-requests")
@login_required
def my_deposit_requests():
    """View user's own deposit requests"""
    requests = q_safe("""
        SELECT request_id, amount, reason, status, requested_at,
               processed_by, processed_at, rejection_reason
        FROM deposit_requests
        WHERE account_number=%s
        ORDER BY requested_at DESC
        LIMIT 50
    """, (session["acc_num"],), fetch="all")

    return render_template("my_deposit_requests.html", requests=requests)


# ═══════════════════════════════════════════════════════════════
#  ADMIN: DEPOSIT REQUEST MANAGEMENT
# ═══════════════════════════════════════════════════════════════

@app.route("/admin/deposit-requests")
@admin_required
def admin_deposit_requests():
    """View all deposit requests"""

    # Get filter from query params
    status_filter = request.args.get("status", "pending")

    if status_filter == "all":
        requests_list = q_safe("""
            SELECT dr.*, a.account_holder, a.phone_number, a.balance, a.is_frozen
            FROM deposit_requests dr
            JOIN accounts a ON dr.account_number = a.account_number
            ORDER BY
                CASE dr.status
                    WHEN 'pending' THEN 0
                    WHEN 'approved' THEN 1
                    WHEN 'rejected' THEN 2
                END,
                dr.requested_at DESC
            LIMIT 100
        """, fetch="all")
    else:
        requests_list = q_safe("""
            SELECT dr.*, a.account_holder, a.phone_number, a.balance, a.is_frozen
            FROM deposit_requests dr
            JOIN accounts a ON dr.account_number = a.account_number
            WHERE dr.status = %s
            ORDER BY dr.requested_at DESC
            LIMIT 100
        """, (status_filter,), fetch="all")

    # Statistics
    stats = q_safe("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected,
            COALESCE(SUM(CASE WHEN status='approved' THEN amount ELSE 0 END), 0) as total_approved_amount,
            COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END), 0) as total_pending_amount
        FROM deposit_requests
    """, fetch="one")

    return render_template("admin_deposit_requests.html",
                          requests=requests_list,
                          stats=stats,
                          current_filter=status_filter,
                          fmt_acc=fmt_acc)


@app.route("/admin/deposit-requests/approve/<request_id>", methods=["POST"])
@admin_required
def admin_approve_deposit(request_id):
    """Approve deposit request and credit amount to user"""

    # Get deposit request
    deposit_req = q_safe("""
        SELECT dr.*, a.account_holder, a.balance, a.is_frozen
        FROM deposit_requests dr
        JOIN accounts a ON dr.account_number = a.account_number
        WHERE dr.request_id = %s
    """, (request_id,), fetch="one")

    if not deposit_req:
        flash("Deposit request not found.", "error")
        return redirect(url_for("admin_deposit_requests"))

    # Check if already processed
    if deposit_req["status"] != "pending":
        flash(f"Request already {deposit_req['status']}.", "warning")
        return redirect(url_for("admin_deposit_requests"))

    # Check if account is frozen
    if deposit_req["is_frozen"]:
        flash("Cannot approve deposit for frozen account. Unfreeze account first.", "error")
        return redirect(url_for("admin_deposit_requests"))

    amount = float(deposit_req["amount"])
    acc_num = deposit_req["account_number"]
    current_balance = float(deposit_req["balance"])

    # Calculate percentage for CIBIL
    if current_balance > 0:
        percentage = (amount / current_balance) * 100
    else:
        percentage = 100

    # Process deposit with transaction
    try:
        with get_db_transaction() as (conn, cur):
            # 1. Credit amount to user account
            if DB_TYPE == "mysql":
                cur.execute("""
                    UPDATE accounts
                    SET balance = balance + %s
                    WHERE account_number = %s
                """, (amount, acc_num))

                # 2. Update deposit request status
                cur.execute("""
                    UPDATE deposit_requests
                    SET status = 'approved',
                        processed_by = 'admin',
                        processed_at = CURRENT_TIMESTAMP
                    WHERE request_id = %s
                """, (request_id,))
            else:
                cur.execute("""
                    UPDATE accounts
                    SET balance = balance + ?
                    WHERE account_number = ?
                """, (amount, acc_num))

                cur.execute("""
                    UPDATE deposit_requests
                    SET status = 'approved',
                        processed_by = 'admin',
                        processed_at = CURRENT_TIMESTAMP
                    WHERE request_id = ?
                """, (request_id,))

        # 3. Calculate and update CIBIL
        cibil_change = calculate_cibil_by_percentage(amount, current_balance, "DEPOSIT")
        update_cibil(acc_num, cibil_change)

        # 4. Log transaction
        log_tx(acc_num, "DEPOSIT_APPROVED", amount,
               f"Admin approved deposit request {request_id} | ${amount:,.2f} ({percentage:.1f}% of balance) → CIBIL +{cibil_change}")

        flash(f"✅ Deposit Approved! | Request: {request_id} | User: {deposit_req['account_holder']} | "
              f"Amount: ${amount:,.2f} credited | CIBIL +{cibil_change}", "success")

    except Exception as e:
        flash(f"❌ Deposit approval failed: {str(e)}", "error")
        return redirect(url_for("admin_deposit_requests"))

    return redirect(url_for("admin_deposit_requests"))


@app.route("/admin/deposit-requests/reject/<request_id>", methods=["POST"])
@admin_required
def admin_reject_deposit(request_id):
    """Reject deposit request"""

    # Get deposit request
    deposit_req = q_safe("SELECT * FROM deposit_requests WHERE request_id=%s",
                         (request_id,), fetch="one")

    if not deposit_req:
        flash("Deposit request not found.", "error")
        return redirect(url_for("admin_deposit_requests"))

    # Check if already processed
    if deposit_req["status"] != "pending":
        flash(f"Request already {deposit_req['status']}.", "warning")
        return redirect(url_for("admin_deposit_requests"))

    # Get rejection reason
    reason = request.form.get("reason", "Did not meet requirements").strip()

    if len(reason) > 500:
        flash("Rejection reason too long (max 500 characters).", "error")
        return redirect(url_for("admin_deposit_requests"))

    # Update request status
    q("""UPDATE deposit_requests
         SET status='rejected',
             processed_by='admin',
             processed_at=CURRENT_TIMESTAMP,
             rejection_reason=%s
         WHERE request_id=%s""",
      (reason, request_id), fetch=None, commit=True)

    # Log
    log_tx(deposit_req["account_number"], "DEPOSIT_REJECTED", deposit_req["amount"],
           f"Admin rejected deposit request {request_id} | Reason: {reason}")

    flash(f"❌ Deposit request {request_id} rejected. Reason: {reason}", "info")
    return redirect(url_for("admin_deposit_requests"))


@app.route("/admin/direct-deposit/<acc_num>", methods=["POST"])
@admin_required
def admin_direct_deposit(acc_num):
    """
    Admin can directly deposit into any account (emergency/correction)
    Bypasses the ticket system
    """

    try:
        amount = float(request.form.get("amount", 0))
    except ValueError:
        flash("Invalid amount.", "error")
        return redirect(url_for("admin_dashboard"))

    # Validate amount
    if amount <= 0:
        flash("Amount must be positive.", "error")
        return redirect(url_for("admin_dashboard"))

    if amount > 100000:
        flash("Maximum deposit amount is $100,000.", "error")
        return redirect(url_for("admin_dashboard"))

    if round(amount, 2) != amount:
        flash("Amount can have maximum 2 decimal places.", "error")
        return redirect(url_for("admin_dashboard"))

    # Get account
    acc = get_account(acc_num)
    if not acc:
        flash("Account not found.", "error")
        return redirect(url_for("admin_dashboard"))

    if acc["is_frozen"]:
        flash("Cannot deposit to frozen account.", "error")
        return redirect(url_for("admin_dashboard"))

    # Get reason
    reason = request.form.get("reason", "Admin direct deposit").strip()

    current_balance = float(acc["balance"])

    # Calculate percentage
    if current_balance > 0:
        percentage = (amount / current_balance) * 100
    else:
        percentage = 100

    # Process deposit
    with get_db_transaction() as (conn, cur):
        if DB_TYPE == "mysql":
            cur.execute("UPDATE accounts SET balance = balance + %s WHERE account_number = %s",
                       (amount, acc_num))
        else:
            cur.execute("UPDATE accounts SET balance = balance + ? WHERE account_number = ?",
                       (amount, acc_num))

    # Update CIBIL
    cibil_change = calculate_cibil_by_percentage(amount, current_balance, "DEPOSIT")
    update_cibil(acc_num, cibil_change)

    # Log
    log_tx(acc_num, "ADMIN_DIRECT_DEPOSIT", amount,
           f"Admin direct deposit: ${amount:,.2f} ({percentage:.1f}% of balance) | Reason: {reason} | CIBIL +{cibil_change}")

    flash(f"✅ Direct Deposit Success | User: {acc['account_holder']} | "
          f"Amount: ${amount:,.2f} | CIBIL +{cibil_change}", "success")

    return redirect(url_for("admin_dashboard"))


#withdraw Route
@app.route("/withdraw", methods=["POST"])
@login_required
def withdraw():
    try:
        amount = float(request.form["amount"])
    except (ValueError, KeyError):
        flash("Invalid amount.", "error")
        return redirect(url_for("dashboard"))

    # Validation
    if amount <= 0:
        flash("Amount must be positive.", "error")
        return redirect(url_for("dashboard"))

    # NEW: Maximum withdrawal limit
    if amount > 100000:
        flash("❌ Maximum withdrawal amount is $100,000 per transaction.", "error")
        return redirect(url_for("dashboard"))

    if round(amount, 2) != amount:
        flash("Amount can have maximum 2 decimal places.", "error")
        return redirect(url_for("dashboard"))

    acc = get_account(session["acc_num"])
    current_balance = float(acc["balance"])

    if current_balance > 0:
        percentage = (amount / current_balance) * 100
    else:
        percentage = 0

    # Use secure_withdraw
    success, msg = secure_withdraw(session["acc_num"], amount)

    if success:
        cibil_change = calculate_cibil_by_percentage(amount, current_balance, "WITHDRAW")
        update_cibil(session["acc_num"], cibil_change)

        log_tx(session["acc_num"], "WITHDRAW", amount,
               f"Withdrawal ${amount:,.2f} ({percentage:.1f}% of balance) → CIBIL {cibil_change}")

        flash(f"${amount:,.2f} withdrawn ({percentage:.1f}% of balance)! 💸 CIBIL {cibil_change}", "success")
    else:
        flash(msg, "error")

    return redirect(url_for("dashboard"))


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        try:
            amount = float(request.form["amount"])
        except:
            flash("Invalid amount.", "error")
            return redirect(url_for("transfer"))

        # Get sender account
        sender = get_account(session["acc_num"])
        sender_balance = float(sender["balance"])

        # Calculate percentage for sender
        if sender_balance > 0:
            sender_percentage = (amount / sender_balance) * 100
        else:
            sender_percentage = 0

        # Get receiver account
        receiver = q_safe("SELECT * FROM accounts WHERE phone_number=%s", (phone,), fetch="one")
        if not receiver:
            flash("Recipient not found.", "error")
            return redirect(url_for("transfer"))

        if receiver["account_number"] == session["acc_num"]:
            flash("Cannot transfer to yourself.", "error")
            return redirect(url_for("transfer"))

        receiver_balance = float(receiver["balance"])

        # Calculate percentage for receiver
        if receiver_balance > 0:
            receiver_percentage = (amount / receiver_balance) * 100
        else:
            receiver_percentage = 100  # First money received

        # Atomic transfer
        success, msg = secure_transfer(session["acc_num"], receiver["account_number"], amount)

        if success:
            # Calculate CIBIL for both parties based on their percentages
            sender_cibil = calculate_cibil_by_percentage(amount, sender_balance, "TRANSFER_OUT")
            receiver_cibil = calculate_cibil_by_percentage(amount, receiver_balance, "TRANSFER_IN")

            update_cibil(session["acc_num"], sender_cibil)
            update_cibil(receiver["account_number"], receiver_cibil)

            # Detailed logging
            desc_sender = f"Sent ${amount:,.2f} to {receiver['account_holder']} ({sender_percentage:.1f}% of balance) → CIBIL {sender_cibil}"
            desc_receiver = f"Received ${amount:,.2f} from {sender['account_holder']} ({receiver_percentage:.1f}% of balance) → CIBIL +{receiver_cibil}"
            log_tx(session["acc_num"], "TRANSFER_OUT", amount, desc_sender)
            log_tx(receiver["account_number"], "TRANSFER_IN", amount, desc_receiver)

            flash(f"${amount:,.2f} sent to {receiver['account_holder']}! ({sender_percentage:.1f}% of balance) ✅ CIBIL {sender_cibil}", "success")
        else:
            flash(msg, "error")

        return redirect(url_for("dashboard"))

    return render_template("transfer.html")




@app.route("/api/lookup-phone", methods=["POST"])
@login_required
def api_lookup_phone():
    phone = request.json.get("phone","").strip()
    acc = q_safe("SELECT account_number,account_holder FROM accounts WHERE phone_number=%s",(phone,),fetch="one")
    if not acc:
        return jsonify(success=False,message="Phone not found.")
    return jsonify(success=True,name=acc["account_holder"],masked="XXXXXXXXXXXX"+acc["account_number"][-4:])


@app.route("/transactions")
@login_required
def transactions():
    txns = q_safe("SELECT log_type,amount,description,created_at FROM transaction_log WHERE account_ref=%s ORDER BY created_at DESC LIMIT 100",(session["acc_num"],),fetch="all")
    return render_template("transactions.html",txns=txns)


@app.route("/cibil")
@login_required
def cibil():
    acc = get_account(session["acc_num"])
    score = acc["cibil_score"]
    if score>=750:   label,advice,color="Excellent","You are eligible for premium loans.","#16a34a"
    elif score>=600: label,advice,color="Good","Keep saving to improve your score.","#ca8a04"
    else:            label,advice,color="Poor","Avoid bouncing transactions to raise your score.","#dc2626"
    return render_template("cibil.html",score=score,label=label,advice=advice,color=color,pct=round(((score-300)/600)*100))

@app.route("/close-account", methods=["POST"])
@login_required
def close_account():
    if request.form.get("confirm")!="CLOSE":
        flash("Type 'CLOSE' to confirm.","error")
        return redirect(url_for("dashboard"))
    acc = get_account(session["acc_num"])
    if float(acc["balance"])>0:
        flash("Cannot close account with remaining balance.","error")
        return redirect(url_for("dashboard"))
    active_loans = q_safe("SELECT COUNT(*) as cnt FROM active_loans WHERE account_number=%s AND status='active'",
                     (session["acc_num"],), fetch="one")
    if active_loans and active_loans["cnt"] > 0:
        flash("Cannot close account with active loans. Please repay all loans first.", "error")
        return redirect(url_for("dashboard"))

    acc_num = session["acc_num"]
    log_tx(acc_num,"ACCOUNT_CLOSED",0,f"Account {acc_num} closed.")
    q("DELETE FROM accounts WHERE account_number=%s",(acc_num,),fetch=None,commit=True)
    session.clear()
    flash("Account permanently closed. Goodbye! 👋","info")
    return redirect(url_for("landing"))

# ═══════════════════════════════════════════════════════════════
#  BANK STATEMENT GENERATION & DOWNLOAD
# ═══════════════════════════════════════════════════════════════

@app.route("/statement/preview")
@login_required
def statement_preview():
    """Preview bank statement in HTML format"""
    acc = get_account(session["acc_num"])

    # Get all transactions
    txns = q_safe("""
        SELECT log_type, amount, description, created_at
        FROM transaction_log
        WHERE account_ref=%s
        ORDER BY created_at DESC
    """, (session["acc_num"],), fetch="all")

    # Get active loans
    active_loans = q_safe("""
        SELECT al.*, lp.name as product_name
        FROM active_loans al
        LEFT JOIN loan_applications la ON al.application_id = la.application_id
        LEFT JOIN loan_products lp ON la.loan_product_id = lp.id
        WHERE al.account_number=%s AND al.status='active'
    """, (session["acc_num"],), fetch="all")

    # Get all loans (paid + active)
    all_loans = q_safe("""
        SELECT al.*, lp.name as product_name
        FROM active_loans al
        LEFT JOIN loan_applications la ON al.application_id = la.application_id
        LEFT JOIN loan_products lp ON la.loan_product_id = lp.id
        WHERE al.account_number=%s
        ORDER BY al.disbursed_at DESC
    """, (session["acc_num"],), fetch="all")

    # Get deposit requests
    deposits = q_safe("""
        SELECT * FROM deposit_requests
        WHERE account_number=%s
        ORDER BY requested_at DESC LIMIT 50
    """, (session["acc_num"],), fetch="all")

    # Calculate statistics
    total_deposits = sum(float(t['amount']) for t in txns if t['log_type'] in ['DEPOSIT', 'DEPOSIT_APPROVED', 'TRANSFER_IN'])
    total_withdrawals = sum(float(t['amount']) for t in txns if t['log_type'] in ['WITHDRAW', 'TRANSFER_OUT'])

    stats = {
        'total_transactions': len(txns),
        'total_deposits': total_deposits,
        'total_withdrawals': total_withdrawals,
        'total_active_loans': len(active_loans),
        'total_inflows': total_deposits,
        'total_outflows': total_withdrawals,
        'statement_date': datetime.now().strftime('%Y-%m-%d'),
    }

    return render_template("statement_preview.html",
                          acc=acc,
                          txns=txns,
                          active_loans=active_loans,
                          all_loans=all_loans,
                          deposits=deposits,
                          stats=stats,
                          fmt_acc=fmt_acc)


@app.route("/statement/download/<format>")
@login_required
def download_statement(format):
    """Download bank statement in PDF or CSV format"""

    if format not in ['pdf', 'csv']:
        flash("Invalid format requested.", "error")
        return redirect(url_for("statement_preview"))

    acc = get_account(session["acc_num"])

    # Get all transactions
    txns = q_safe("""
        SELECT log_type, amount, description, created_at
        FROM transaction_log
        WHERE account_ref=%s
        ORDER BY created_at DESC
    """, (session["acc_num"],), fetch="all")

    # Get active loans
    active_loans = q_safe("""
        SELECT al.*, lp.name as product_name
        FROM active_loans al
        LEFT JOIN loan_applications la ON al.application_id = la.application_id
        LEFT JOIN loan_products lp ON la.loan_product_id = lp.id
        WHERE al.account_number=%s AND al.status='active'
    """, (session["acc_num"],), fetch="all")

    # Get all loans (paid + active)
    all_loans = q_safe("""
        SELECT al.*, lp.name as product_name
        FROM active_loans al
        LEFT JOIN loan_applications la ON al.application_id = la.application_id
        LEFT JOIN loan_products lp ON la.loan_product_id = lp.id
        WHERE al.account_number=%s
        ORDER BY al.disbursed_at DESC
    """, (session["acc_num"],), fetch="all")

    if format == 'pdf':
        return _generate_pdf_statement(acc, txns, active_loans, all_loans)
    else:  # csv
        return _generate_csv_statement(acc, txns, active_loans, all_loans)


def _generate_pdf_statement(acc, txns, active_loans, all_loans):
    """Generate PDF bank statement"""

    # Create PDF in memory
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []

    # Define styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#1e293b'),
        alignment=TA_LEFT
    )

    # Header
    story.append(Paragraph("PyBank - Account Statement", title_style))
    story.append(Spacer(1, 0.2*inch))

    # Account Info Section
    story.append(Paragraph("Account Information", heading_style))

    account_data = [
        ['Field', 'Details'],
        ['Account Holder', acc['account_holder']],
        ['Account Number', fmt_acc(acc['account_number'])],
        ['Account Type', acc['account_type'].replace('Account', '')],
        ['Phone Number', acc['phone_number']],
        ['Current Balance', f"${float(acc['balance']):.2f}"],
        ['CIBIL Score', str(acc['cibil_score'])],
        ['Status', 'Frozen' if acc['is_frozen'] else 'Active'],
        ['Statement Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
    ]

    account_table = Table(account_data, colWidths=[2.5*inch, 3.5*inch])
    account_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f4f8')),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(account_table)
    story.append(Spacer(1, 0.3*inch))

    # Summary Statistics
    story.append(Paragraph("Summary Statistics", heading_style))

    total_deposits = sum(float(t['amount']) for t in txns if t['log_type'] in ['DEPOSIT', 'DEPOSIT_APPROVED', 'TRANSFER_IN'])
    total_withdrawals = sum(float(t['amount']) for t in txns if t['log_type'] in ['WITHDRAW', 'TRANSFER_OUT'])

    summary_data = [
        ['Metric', 'Amount'],
        ['Total Deposits', f"${total_deposits:.2f}"],
        ['Total Withdrawals', f"${total_withdrawals:.2f}"],
        ['Net Flow', f"${total_deposits - total_withdrawals:.2f}"],
        ['Total Transactions', str(len(txns))],
    ]

    summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#10b981')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f4f8')),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))

    # Recent Transactions
    story.append(Paragraph("Transaction History (Last 50)", heading_style))

    tx_data = [['Date', 'Type', 'Description', 'Amount']]
    for i, t in enumerate(txns[:50]):
        tx_data.append([
            str(t['created_at'])[:19],
            t['log_type'].replace('_', ' '),
            t['description'][:40] if t['description'] else '-',
            f"${float(t['amount']):.2f}" if t['amount'] else '-'
        ])

    tx_table = Table(tx_data, colWidths=[1.5*inch, 1.5*inch, 5*inch, 1.1*inch])
    tx_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f4f8')),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(tx_table)

    # Page Break for Loans Section
    if all_loans:
        story.append(PageBreak())
        story.append(Paragraph("Loan Information", heading_style))

        loan_data = [['Loan ID', 'Product', 'Amount', 'Outstanding', 'Status']]
        for loan in all_loans:
            loan_data.append([
                loan['loan_id'][:12],
                loan.get('product_name', 'N/A')[:20],
                f"${float(loan['principal_amount']):.2f}",
                f"${float(loan['outstanding_balance']):.2f}",
                loan['status'].capitalize()
            ])

        loan_table = Table(loan_data, colWidths=[1.3*inch, 1.8*inch, 1.3*inch, 1.3*inch, 1.3*inch])
        loan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7c3aed')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f4f8')),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        story.append(loan_table)

    # Footer
    story.append(Spacer(1, 0.3*inch))
    footer_text = f"<b>Statement Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>" \
                  f"<b>Document ID:</b> {acc['account_number'][-4:]}-{datetime.now().strftime('%Y%m%d%H%M%S')}<br/>" \
                  f"<i>This is a computer-generated document. No signature is required.</i>"
    story.append(Paragraph(footer_text, normal_style))

    # Build PDF
    doc.build(story)
    pdf_buffer.seek(0)

    # Return as downloadable file
    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"PyBank_Statement_{acc['account_number']}_{datetime.now().strftime('%Y%m%d')}.pdf"
    )


def _generate_csv_statement(acc, txns, active_loans, all_loans):
    """Generate CSV bank statement"""

    # Write CSV using StringIO
    csv_content = io.StringIO()
    writer = csv.writer(csv_content)

    # Header
    writer.writerow(['PyBank - Account Statement'])
    writer.writerow([])
    writer.writerow(['ACCOUNT INFORMATION'])
    writer.writerow(['Field', 'Value'])
    writer.writerow(['Account Holder', acc['account_holder']])
    writer.writerow(['Account Number', fmt_acc(acc['account_number'])])
    writer.writerow(['Account Type', acc['account_type'].replace('Account', '')])
    writer.writerow(['Phone Number', acc['phone_number']])
    writer.writerow(['Current Balance', f"${float(acc['balance']):.2f}"])
    writer.writerow(['CIBIL Score', acc['cibil_score']])
    writer.writerow(['Status', 'Frozen' if acc['is_frozen'] else 'Active'])
    writer.writerow(['Statement Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])

    # Summary Statistics
    total_deposits = sum(float(t['amount']) for t in txns if t['log_type'] in ['DEPOSIT', 'DEPOSIT_APPROVED', 'TRANSFER_IN'])
    total_withdrawals = sum(float(t['amount']) for t in txns if t['log_type'] in ['WITHDRAW', 'TRANSFER_OUT'])

    writer.writerow(['SUMMARY STATISTICS'])
    writer.writerow(['Metric', 'Amount'])
    writer.writerow(['Total Deposits', f"${total_deposits:.2f}"])
    writer.writerow(['Total Withdrawals', f"${total_withdrawals:.2f}"])
    writer.writerow(['Net Flow', f"${total_deposits - total_withdrawals:.2f}"])
    writer.writerow(['Total Transactions', len(txns)])
    writer.writerow([])

    # Transactions
    writer.writerow(['TRANSACTION HISTORY'])
    writer.writerow(['Date', 'Type', 'Description', 'Amount'])
    for t in txns:
        writer.writerow([
            str(t['created_at'])[:19],
            t['log_type'].replace('_', ' '),
            t['description'] if t['description'] else '-',
            f"${float(t['amount']):.2f}" if t['amount'] else '-'
        ])
    writer.writerow([])

    # Loans
    if all_loans:
        writer.writerow(['LOAN INFORMATION'])
        writer.writerow(['Loan ID', 'Product Name', 'Principal Amount', 'Outstanding Balance', 'EMI Amount', 'Status'])
        for loan in all_loans:
            writer.writerow([
                loan['loan_id'],
                loan.get('product_name', 'N/A'),
                f"${float(loan['principal_amount']):.2f}",
                f"${float(loan['outstanding_balance']):.2f}",
                f"${float(loan['emi_amount']):.2f}",
                loan['status'].capitalize()
            ])
        writer.writerow([])

    # Footer
    writer.writerow([])
    writer.writerow([f"Document Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"])
    writer.writerow([f"Document ID: {acc['account_number'][-4:]}-{datetime.now().strftime('%Y%m%d%H%M%S')}"])

    # Convert StringIO to bytes
    csv_bytes = csv_content.getvalue().encode('utf-8')
    csv_buffer = BytesIO(csv_bytes)

    return send_file(
        csv_buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"PyBank_Statement_{acc['account_number']}_{datetime.now().strftime('%Y%m%d')}.csv"
    )


# ═══════════════════════════════════════════════════════════════
#  LOAN ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/loans")
@login_required
def loans_marketplace():
    acc = get_account(session["acc_num"])
    products = q_safe("SELECT * FROM loan_products WHERE active=1 ORDER BY min_cibil_score DESC", fetch="all")

    for p in products:
        p["eligible"] = acc["cibil_score"] >= p["min_cibil_score"]
        p["discount"] = get_cibil_discount(acc["cibil_score"])
        p["your_rate"] = max(0.05, float(p["interest_rate"]) - p["discount"])

    active = q_safe("SELECT * FROM active_loans WHERE account_number=%s AND status='active' ORDER BY disbursed_at DESC",
               (session["acc_num"],), fetch="all")
    pending = q_safe("""SELECT la.*, lp.name as product_name FROM loan_applications la
                   JOIN loan_products lp ON la.loan_product_id=lp.id
                   WHERE la.account_number=%s AND la.status='pending'
                   ORDER BY la.created_at DESC""",
                (session["acc_num"],), fetch="all")

    return render_template("loans.html", products=products, active=active, pending=pending,
                          acc=acc, fmt_acc=fmt_acc)


@app.route("/loans/apply/<int:product_id>", methods=["GET", "POST"])
@login_required
def loan_apply(product_id):
    product = q_safe("SELECT * FROM loan_products WHERE id=%s", (product_id,), fetch="one")
    if not product:
        flash("Loan product not found.", "error")
        return redirect(url_for("loans_marketplace"))

    acc = get_account(session["acc_num"])

    if request.method == "POST":
        try:
            amount = float(request.form.get("amount", 0))
            tenure = int(request.form.get("tenure", 0))
            purpose = request.form.get("purpose", "").strip()
        except ValueError:
            flash("Invalid input values.", "error")
            return render_template("loan_apply.html", product=product, acc=acc)

        eligible, msg, adj_rate = check_loan_eligibility(acc, product, amount, tenure)
        if not eligible:
            flash(msg, "error")
            return render_template("loan_apply.html", product=product, acc=acc)

        emi = calculate_emi(amount, adj_rate, tenure)
        app_id = gen_loan_id("APP")

        q("""INSERT INTO loan_applications(application_id,account_number,loan_product_id,
            amount,tenure_months,interest_rate,emi_amount,purpose,status,cibil_at_application)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'pending',%s)""",
          (app_id, session["acc_num"], product_id, amount, tenure, adj_rate, emi, purpose, acc["cibil_score"]),
          fetch=None, commit=True)

        log_tx(session["acc_num"], "LOAN_APPLIED", amount,
               f"Applied for {product['name']} - {app_id}")

        flash(f"Loan application submitted! Application ID: {app_id}. EMI: ${emi:,.2f}/month", "success")
        return redirect(url_for("loans_marketplace"))

    return render_template("loan_apply.html", product=product, acc=acc)


@app.route("/loans/my-loans")
@login_required
def my_loans():
    active = q_safe("""SELECT al.*, lp.name as product_name FROM active_loans al
                  LEFT JOIN loan_applications la ON al.application_id = la.application_id
                  LEFT JOIN loan_products lp ON la.loan_product_id = lp.id
                  WHERE al.account_number=%s
                  ORDER BY al.status='active' DESC, al.disbursed_at DESC""",
               (session["acc_num"],), fetch="all")

    applications = q_safe("""SELECT la.*, lp.name as product_name FROM loan_applications la
                        JOIN loan_products lp ON la.loan_product_id=lp.id
                        WHERE la.account_number=%s
                        ORDER BY la.created_at DESC LIMIT 20""",
                     (session["acc_num"],), fetch="all")

    return render_template("my_loans.html", active=active, applications=applications, fmt_acc=fmt_acc)


@app.route("/loans/pay-emi/<loan_id>", methods=["POST"])
@login_required
def pay_emi(loan_id):
    loan = q_safe("SELECT * FROM active_loans WHERE loan_id=%s AND account_number=%s",
             (loan_id, session["acc_num"]), fetch="one")
    if not loan:
        flash("Loan not found.", "error")
        return redirect(url_for("my_loans"))

    if loan["status"] != "active":
        flash("This loan is not active.", "error")
        return redirect(url_for("my_loans"))

    emi_amt = float(loan["emi_amount"])

    # SECURITY: Use secure_withdraw for EMI payment
    success, msg = secure_withdraw(session["acc_num"], emi_amt)

    if not success:
        flash(f"Payment failed: {msg}", "error")
        return redirect(url_for("my_loans"))

    # Calculate principal and interest split
    outstanding = float(loan["outstanding_balance"])
    monthly_rate = float(loan["interest_rate"]) / 12
    interest_portion = outstanding * monthly_rate
    principal_portion = emi_amt - interest_portion
    new_outstanding = outstanding - principal_portion

    payment_id = gen_loan_id("PAY")
    emi_num = loan["emis_paid"] + 1

    q("""INSERT INTO emi_payments(payment_id,loan_id,emi_number,amount_paid,
        principal_paid,interest_paid,outstanding_after,status)
        VALUES(%s,%s,%s,%s,%s,%s,%s,'paid')""",
      (payment_id, loan_id, emi_num, emi_amt, principal_portion, interest_portion, max(0, new_outstanding)),
      fetch=None, commit=True)

    emis_remaining = loan["emis_remaining"] - 1
    new_status = "closed" if emis_remaining == 0 else "active"

    q("""UPDATE active_loans SET outstanding_balance=%s, emis_paid=emis_paid+1,
        emis_remaining=%s, status=%s WHERE loan_id=%s""",
      (max(0, new_outstanding), emis_remaining, new_status, loan_id), fetch=None, commit=True)

    log_tx(session["acc_num"], "EMI_PAID", emi_amt,
           f"EMI {emi_num}/{loan['tenure_months']} paid for {loan_id}")

    update_cibil(session["acc_num"], 3)

    if new_status == "closed":
        flash(f"🎉 Loan fully repaid! Final EMI of ${emi_amt:,.2f} paid. CIBIL +3", "success")
        log_tx(session["acc_num"], "LOAN_CLOSED", 0, f"Loan {loan_id} fully repaid")
        update_cibil(session["acc_num"], 15)
    else:
        flash(f"EMI paid successfully! ${emi_amt:,.2f} deducted. {emis_remaining} EMIs remaining. CIBIL +3", "success")

    return redirect(url_for("my_loans"))


@app.route("/api/loan/calculate-emi", methods=["POST"])
@login_required
def api_calculate_emi():
    data = request.json or {}
    try:
        product_id = int(data.get("product_id"))
        amount = float(data.get("amount", 0))
        tenure = int(data.get("tenure", 0))
    except (ValueError, TypeError):
        return jsonify(success=False, message="Invalid inputs"), 400

    product = q_safe("SELECT * FROM loan_products WHERE id=%s", (product_id,), fetch="one")
    acc = get_account(session["acc_num"])

    if not product:
        return jsonify(success=False, message="Product not found"), 404

    eligible, msg, adj_rate = check_loan_eligibility(acc, product, amount, tenure)

    if not eligible:
        return jsonify(success=False, message=msg, eligible=False)

    emi = calculate_emi(amount, adj_rate, tenure)
    total = emi * tenure
    total_interest = total - amount

    return jsonify(
        success=True,
        eligible=True,
        emi=round(emi, 2),
        total_payable=round(total, 2),
        total_interest=round(total_interest, 2),
        interest_rate=round(adj_rate * 100, 2),
        discount=round(get_cibil_discount(acc["cibil_score"]) * 100, 2)
    )


# ═══════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method=="POST":
        if request.form.get("key")==ADMIN_KEY:
            session["is_admin"]=True
            flash("Admin access granted.","success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin key.","error")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin",None)
    flash("Admin logged out.","info")
    return redirect(url_for("landing"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    stats = q_safe("""SELECT COUNT(*) as total_accounts,COALESCE(SUM(balance),0) as total_balance,
        SUM(CASE WHEN account_type='SavingsAccount' THEN 1 ELSE 0 END) as savings,
        SUM(CASE WHEN account_type='CheckingAccount' THEN 1 ELSE 0 END) as checking,
        SUM(CASE WHEN is_frozen=1 THEN 1 ELSE 0 END) as frozen FROM accounts""",fetch="one")
    log_stats = q_safe("SELECT log_type,COALESCE(SUM(amount),0) as total FROM transaction_log GROUP BY log_type",fetch="all")
    log_map = {r["log_type"]:float(r["total"]) for r in log_stats}
    accounts = q_safe("SELECT account_number,account_holder,phone_number,account_type,balance,is_frozen,cibil_score,created_at FROM accounts ORDER BY created_at DESC",fetch="all")
    recent_logs = q_safe("SELECT * FROM transaction_log ORDER BY created_at DESC LIMIT 20",fetch="all")
    return render_template("admin.html",stats=stats,log_map=log_map,accounts=accounts,recent_logs=recent_logs,fmt_acc=fmt_acc)


@app.route("/admin/freeze/<acc_num>", methods=["POST"])
@admin_required
def admin_freeze(acc_num):
    acc = get_account(acc_num)
    if not acc:
        flash("Account not found.","error")
        return redirect(url_for("admin_dashboard"))
    new_status = 0 if acc["is_frozen"] else 1
    q("UPDATE accounts SET is_frozen=%s WHERE account_number=%s",(new_status,acc_num),fetch=None,commit=True)
    log_tx(acc_num,"ADMIN_FREEZE",0,f"Admin set {acc_num} to {'FROZEN' if new_status else 'ACTIVE'}")
    flash(f"Account {fmt_acc(acc_num)} is now {'FROZEN' if new_status else 'ACTIVE'}.","success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/apply-interest", methods=["POST"])
@admin_required
def admin_apply_interest():
    savings = q_safe("SELECT account_number,balance,interest_rate FROM accounts WHERE account_type='SavingsAccount' AND balance>0",fetch="all")
    total,count = 0.0,0
    for acc in savings:
        interest = float(acc["balance"]) * float(acc["interest_rate"])
        q("UPDATE accounts SET balance=balance+%s WHERE account_number=%s",(interest,acc["account_number"]),fetch=None,commit=True)
        log_tx(acc["account_number"],"INTEREST",interest,"5% interest applied")
        total+=interest; count+=1
    flash(f"Applied ${total:,.2f} interest to {count} savings accounts. 📈","success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/search-logs")
@admin_required
def admin_search_logs():
    query = request.args.get("q","").strip()
    logs = q_safe("SELECT * FROM transaction_log WHERE account_ref LIKE %s OR description LIKE %s ORDER BY created_at DESC LIMIT 100",(f"%{query}%",f"%{query}%"),fetch="all") if query else []
    return render_template("admin_logs.html",logs=logs,query=query)


@app.route("/admin/factory-reset", methods=["POST"])
@admin_required
def admin_factory_reset():
    if request.form.get("confirm")!="DELETE":
        flash("Type DELETE to confirm.","error")
        return redirect(url_for("admin_dashboard"))
    q("DELETE FROM transaction_log",fetch=None,commit=True)
    q("DELETE FROM accounts",fetch=None,commit=True)
    session.clear()
    flash("System reset. All data wiped. ♻️","info")
    return redirect(url_for("landing"))


@app.route("/admin/loans")
@admin_required
def admin_loans():
    pending_apps = q_safe("""SELECT la.*, lp.name as product_name, a.account_holder, a.cibil_score
                        FROM loan_applications la
                        JOIN loan_products lp ON la.loan_product_id=lp.id
                        JOIN accounts a ON la.account_number=a.account_number
                        WHERE la.status='pending'
                        ORDER BY la.created_at DESC""", fetch="all")

    active_loans = q_safe("""SELECT al.*, a.account_holder, a.account_number
                        FROM active_loans al
                        JOIN accounts a ON al.account_number=a.account_number
                        WHERE al.status='active'
                        ORDER BY al.disbursed_at DESC""", fetch="all")

    all_apps = q_safe("""SELECT la.*, lp.name as product_name, a.account_holder
                    FROM loan_applications la
                    JOIN loan_products lp ON la.loan_product_id=lp.id
                    JOIN accounts a ON la.account_number=a.account_number
                    ORDER BY la.created_at DESC LIMIT 50""", fetch="all")

    stats = {
        "pending": len(pending_apps),
        "active": len(active_loans),
        "total_disbursed": sum(float(l["principal_amount"]) for l in active_loans),
        "total_outstanding": sum(float(l["outstanding_balance"]) for l in active_loans),
    }

    return render_template("admin_loans.html",
                          pending=pending_apps, active=active_loans,
                          all_apps=all_apps, stats=stats, fmt_acc=fmt_acc)


@app.route("/admin/loans/approve/<app_id>", methods=["POST"])
@admin_required
def admin_approve_loan(app_id):
    app = q_safe("SELECT * FROM loan_applications WHERE application_id=%s", (app_id,), fetch="one")
    if not app:
        flash("Application not found.", "error")
        return redirect(url_for("admin_loans"))

    if app["status"] != "pending":
        flash("Application already processed.", "error")
        return redirect(url_for("admin_loans"))

    loan_id = gen_loan_id("LN")
    total_amount = float(app["emi_amount"]) * app["tenure_months"]

    # SECURITY: Use transaction for atomic loan approval + disbursement
    with get_db_transaction() as (conn, cur):
        # Create active loan
        if DB_TYPE == "mysql":
            cur.execute("""INSERT INTO active_loans(loan_id,application_id,account_number,
                principal_amount,interest_rate,tenure_months,emi_amount,total_amount,
                outstanding_balance,emis_remaining,status)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'active')""",
              (loan_id, app_id, app["account_number"], app["amount"], app["interest_rate"],
               app["tenure_months"], app["emi_amount"], total_amount, app["amount"],
               app["tenure_months"]))

            # Update application status
            cur.execute("""UPDATE loan_applications SET status='approved',approved_by='admin',
                approved_at=CURRENT_TIMESTAMP WHERE application_id=%s""", (app_id,))

            # Disburse funds
            cur.execute("UPDATE accounts SET balance=balance+%s WHERE account_number=%s",
                      (app["amount"], app["account_number"]))
        else:
            cur.execute("""INSERT INTO active_loans(loan_id,application_id,account_number,
                principal_amount,interest_rate,tenure_months,emi_amount,total_amount,
                outstanding_balance,emis_remaining,status)
                VALUES(?,?,?,?,?,?,?,?,?,?,'active')""",
              (loan_id, app_id, app["account_number"], app["amount"], app["interest_rate"],
               app["tenure_months"], app["emi_amount"], total_amount, app["amount"],
               app["tenure_months"]))

            cur.execute("""UPDATE loan_applications SET status='approved',approved_by='admin'
                WHERE application_id=?""", (app_id,))

            cur.execute("UPDATE accounts SET balance=balance+? WHERE account_number=?",
                      (app["amount"], app["account_number"]))

    log_tx(app["account_number"], "LOAN_DISBURSED", app["amount"],
           f"Loan {loan_id} approved and disbursed - {app_id}")

    update_cibil(app["account_number"], 10)

    flash(f"Loan approved! ${app['amount']:,.2f} disbursed. Loan ID: {loan_id}", "success")
    return redirect(url_for("admin_loans"))


@app.route("/admin/loans/reject/<app_id>", methods=["POST"])
@admin_required
def admin_reject_loan(app_id):
    reason = request.form.get("reason", "Did not meet criteria").strip()
    app = q_safe("SELECT * FROM loan_applications WHERE application_id=%s", (app_id,), fetch="one")

    if not app:
        flash("Application not found.", "error")
        return redirect(url_for("admin_loans"))

    if app["status"] != "pending":
        flash("Application already processed.", "error")
        return redirect(url_for("admin_loans"))

    q("""UPDATE loan_applications SET status='rejected',rejection_reason=%s
        WHERE application_id=%s""", (reason, app_id), fetch=None, commit=True)

    log_tx(app["account_number"], "LOAN_REJECTED", 0,
           f"Loan application {app_id} rejected: {reason}")

    flash(f"Loan application {app_id} rejected.", "info")
    return redirect(url_for("admin_loans"))


# ═══════════════════════════════════════════════════════════════
#  CHAT API — CUSTOMER SIDE
# ═══════════════════════════════════════════════════════════════

@app.route("/api/chat/init", methods=["POST"])
def chat_init():
    acc_num = session.get("acc_num")
    name = session.get("acc_name", "Guest")
    cs = get_or_create_chat(acc_num, name)
    return jsonify(success=True, token=cs["session_token"],
                   status=cs["status"], name=cs["customer_name"])


@app.route("/api/chat/send", methods=["POST"])
def chat_send():
    data = request.json or {}
    token = data.get("token") or session.get("chat_token")
    message = (data.get("message") or "").strip()

    if not token or not message:
        return jsonify(success=False, message="Missing fields"), 400

    cs = q_safe("SELECT * FROM chat_sessions WHERE session_token=%s", (token,), fetch="one")
    if not cs:
        return jsonify(success=False, message="Session not found"), 404

    save_msg(token, "customer", cs["customer_name"], message, "text")
    reply_msgs = []

    if cs["status"] == "bot":
        reply_text, should_escalate = bot_reply(message, cs.get("account_number"))
        save_msg(token, "bot", BOT_NAME, reply_text, "text")
        reply_msgs.append({"sender_type":"bot","sender_name":BOT_NAME,"message":reply_text,"msg_type":"text"})

        if should_escalate:
            q("UPDATE chat_sessions SET status='waiting' WHERE session_token=%s",(token,),fetch=None,commit=True)
            sys_msg = "⏳ Your chat has been transferred to our support queue. An agent will join shortly."
            save_msg(token, "system", "System", sys_msg, "system")
            reply_msgs.append({"sender_type":"system","sender_name":"System","message":sys_msg,"msg_type":"system"})

    return jsonify(success=True, replies=reply_msgs)


@app.route("/api/chat/poll", methods=["POST"])
def chat_poll():
    data = request.json or {}
    token = data.get("token") or session.get("chat_token")
    since = int(data.get("since_id", 0))

    if not token:
        return jsonify(success=False), 400

    msgs = q_safe("SELECT id,sender_type,sender_name,message,msg_type,created_at FROM chat_messages WHERE session_token=%s AND id>%s ORDER BY id ASC",
             (token, since), fetch="all")
    cs = q_safe("SELECT status,unread_count FROM chat_sessions WHERE session_token=%s",(token,),fetch="one")
    q("UPDATE chat_sessions SET unread_count=0 WHERE session_token=%s",(token,),fetch=None,commit=True)
    return jsonify(success=True, messages=msgs, status=cs["status"] if cs else "unknown")

@app.route("/api/chat/quick", methods=["POST"])
def chat_quick():
    data = request.json or {}
    token = data.get("token") or session.get("chat_token")
    topic = (data.get("topic") or "").strip()

    if not token or not topic:
        return jsonify(success=False), 400

    cs = q_safe("SELECT * FROM chat_sessions WHERE session_token=%s",(token,),fetch="one")
    if not cs:
        return jsonify(success=False), 404

    save_msg(token, "customer", cs["customer_name"], topic, "text")
    reply_text, should_escalate = bot_reply(topic, cs.get("account_number"))
    save_msg(token, "bot", BOT_NAME, reply_text, "text")

    if should_escalate:
        q("UPDATE chat_sessions SET status='waiting' WHERE session_token=%s",(token,),fetch=None,commit=True)
        save_msg(token,"system","System","⏳ Transferring to a live agent...","system")

    return jsonify(success=True)


@app.route("/api/chat/close", methods=["POST"])
def chat_close():
    token = (request.json or {}).get("token") or session.get("chat_token")
    if token:
        q("UPDATE chat_sessions SET status='closed' WHERE session_token=%s",(token,),fetch=None,commit=True)
        save_msg(token,"system","System","Chat session closed by customer.","system")
    return jsonify(success=True)


@app.route("/api/chat/rate", methods=["POST"])
def chat_rate():
    data = request.json or {}
    token = data.get("token")
    rating = data.get("rating",5)
    if token:
        save_msg(token,"system","System",f"⭐ Customer rated this chat: {rating}/5","rating")
        q("UPDATE chat_sessions SET status='closed' WHERE session_token=%s",(token,),fetch=None,commit=True)
    return jsonify(success=True)


# ═══════════════════════════════════════════════════════════════
#  CHAT API — AGENT (ADMIN) SIDE
# ═══════════════════════════════════════════════════════════════

@app.route("/admin/support")
@admin_required
def admin_support():
    canned = q_safe("SELECT * FROM canned_responses ORDER BY shortcut", fetch="all")
    return render_template("support.html", canned=canned)


@app.route("/api/support/sessions", methods=["GET"])
@admin_required
def support_sessions():
    sessions_list = q_safe("""SELECT session_token,customer_name,status,unread_count,updated_at,account_number,created_at
        FROM chat_sessions WHERE status IN ('waiting','active','bot')
        ORDER BY CASE status WHEN 'waiting' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, updated_at DESC""",
        fetch="all")
    return jsonify(success=True, sessions=sessions_list)


@app.route("/api/support/messages/<token>", methods=["GET"])
@admin_required
def support_get_messages(token):
    since = int(request.args.get("since_id", 0))
    msgs = q_safe("SELECT id,sender_type,sender_name,message,msg_type,created_at FROM chat_messages WHERE session_token=%s AND id>%s ORDER BY id ASC",
              (token, since), fetch="all")
    cs = q_safe("SELECT * FROM chat_sessions WHERE session_token=%s",(token,),fetch="one")
    q("UPDATE chat_sessions SET unread_count=0 WHERE session_token=%s",(token,),fetch=None,commit=True)
    return jsonify(success=True, messages=msgs, session=cs)


@app.route("/api/support/reply", methods=["POST"])
@admin_required
def support_reply():
    data = request.json or {}
    token = data.get("token")
    message = (data.get("message") or "").strip()

    if not token or not message:
        return jsonify(success=False), 400

    save_msg(token, "agent", "Support Agent", message, "text")
    q("UPDATE chat_sessions SET status='active',agent_id='admin',unread_count=0 WHERE session_token=%s",(token,),fetch=None,commit=True)
    return jsonify(success=True)


@app.route("/api/support/take/<token>", methods=["POST"])
@admin_required
def support_take(token):
    cs = q_safe("SELECT status FROM chat_sessions WHERE session_token=%s",(token,),fetch="one")
    if not cs:
        return jsonify(success=False), 404

    q("UPDATE chat_sessions SET status='active',agent_id='admin' WHERE session_token=%s",(token,),fetch=None,commit=True)
    save_msg(token,"system","System","🎧 A support agent has joined the conversation. How can we help you?","system")
    return jsonify(success=True)


@app.route("/api/support/close/<token>", methods=["POST"])
@admin_required
def support_close(token):
    save_msg(token,"system","System","✅ This chat has been resolved and closed by the support team. Thank you for contacting PyBank!","system")
    q("UPDATE chat_sessions SET status='closed' WHERE session_token=%s",(token,),fetch=None,commit=True)
    return jsonify(success=True)


@app.route("/api/support/stats", methods=["GET"])
@admin_required
def support_stats():
    waiting = len(q_safe("SELECT 1 FROM chat_sessions WHERE status='waiting'",fetch="all") or [])
    active = len(q_safe("SELECT 1 FROM chat_sessions WHERE status='active'", fetch="all") or [])
    bot = len(q_safe("SELECT 1 FROM chat_sessions WHERE status='bot'", fetch="all") or [])
    closed = len(q_safe("SELECT 1 FROM chat_sessions WHERE status='closed'", fetch="all") or [])
    return jsonify(success=True, waiting=waiting, active=active, bot=bot, closed=closed)


@app.route("/api/support/canned/save", methods=["POST"])
@admin_required
def support_save_canned():
    data = request.json or {}
    shortcut = (data.get("shortcut","")).strip().lower()
    response = (data.get("response","")).strip()

    if not shortcut or not response:
        return jsonify(success=False),400

    if q_safe("SELECT 1 FROM canned_responses WHERE shortcut=%s",(shortcut,),fetch="one"):
        q("UPDATE canned_responses SET response=%s WHERE shortcut=%s",(response,shortcut),fetch=None,commit=True)
    else:
        q("INSERT INTO canned_responses(shortcut,response) VALUES(%s,%s)",(shortcut,response),fetch=None,commit=True)

    return jsonify(success=True)

# ═══════════════════════════════════════════════════════════════
#  ADMIN: CLOSE ACCOUNT
# ═══════════════════════════════════════════════════════════════

@app.route("/admin/close-account/<acc_num>", methods=["POST"])
@admin_required
def admin_close_account(acc_num):
    """
    Admin can close any account
    Requirements:
    1. Balance must be $0
    2. No active loans
    3. Confirmation required
    """

    # Get confirmation
    confirm = request.form.get("confirm", "").strip()
    if confirm != "CLOSE":
        flash("Type 'CLOSE' to confirm account closure.", "error")
        return redirect(url_for("admin_dashboard"))

    # Get account details
    acc = get_account(acc_num)
    if not acc:
        flash("Account not found.", "error")
        return redirect(url_for("admin_dashboard"))

    # Check balance
    if float(acc["balance"]) != 0:
        flash(f"Cannot close account with balance ${float(acc['balance']):,.2f}. Balance must be $0.", "error")
        return redirect(url_for("admin_dashboard"))

    # Check active loans
    active_loans = q_safe(
        "SELECT COUNT(*) as cnt FROM active_loans WHERE account_number=%s AND status='active'",
        (acc_num,),
        fetch="one"
    )

    if active_loans and active_loans["cnt"] > 0:
        flash(f"Cannot close account with {active_loans['cnt']} active loan(s). All loans must be repaid first.", "error")
        return redirect(url_for("admin_dashboard"))

    # Store account details for logging
    account_holder = acc["account_holder"]
    phone_number = acc["phone_number"]

    # Log the closure before deleting
    log_tx(acc_num, "ADMIN_ACCOUNT_CLOSED", 0,
           f"Admin closed account for {account_holder} (Phone: {phone_number})")

    # Delete account and all related data
    with get_db_transaction() as (conn, cur):
        if DB_TYPE == "mysql":
            # Delete in order (foreign key constraints)
            cur.execute("DELETE FROM emi_payments WHERE loan_id IN (SELECT loan_id FROM active_loans WHERE account_number=%s)", (acc_num,))
            cur.execute("DELETE FROM active_loans WHERE account_number=%s", (acc_num,))
            cur.execute("DELETE FROM loan_applications WHERE account_number=%s", (acc_num,))
            cur.execute("DELETE FROM chat_messages WHERE session_token IN (SELECT session_token FROM chat_sessions WHERE account_number=%s)", (acc_num,))
            cur.execute("DELETE FROM chat_sessions WHERE account_number=%s", (acc_num,))
            cur.execute("DELETE FROM transaction_log WHERE account_ref=%s", (acc_num,))
            cur.execute("DELETE FROM accounts WHERE account_number=%s", (acc_num,))
        else:
            # SQLite
            cur.execute("DELETE FROM emi_payments WHERE loan_id IN (SELECT loan_id FROM active_loans WHERE account_number=?)", (acc_num,))
            cur.execute("DELETE FROM active_loans WHERE account_number=?", (acc_num,))
            cur.execute("DELETE FROM loan_applications WHERE account_number=?", (acc_num,))
            cur.execute("DELETE FROM chat_messages WHERE session_token IN (SELECT session_token FROM chat_sessions WHERE account_number=?)", (acc_num,))
            cur.execute("DELETE FROM chat_sessions WHERE account_number=?", (acc_num,))
            cur.execute("DELETE FROM transaction_log WHERE account_ref=?", (acc_num,))
            cur.execute("DELETE FROM accounts WHERE account_number=?", (acc_num,))

    flash(f"✅ Account {fmt_acc(acc_num)} for {account_holder} has been permanently closed by admin.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/force-close-account/<acc_num>", methods=["POST"])
@admin_required
def admin_force_close_account(acc_num):
    """
    Admin can FORCE close an account even with balance/loans
    Use with extreme caution!
    Requires: Type "FORCE CLOSE" to confirm
    """

    # Double confirmation required
    confirm = request.form.get("confirm", "").strip()
    if confirm != "FORCE CLOSE":
        flash("Type 'FORCE CLOSE' (all caps) to confirm forced closure.", "error")
        return redirect(url_for("admin_dashboard"))

    # Get account details
    acc = get_account(acc_num)
    if not acc:
        flash("Account not found.", "error")
        return redirect(url_for("admin_dashboard"))

    # Store details for logging
    account_holder = acc["account_holder"]
    phone_number = acc["phone_number"]
    balance = float(acc["balance"])

    # Check for active loans
    active_loans = q_safe(
        "SELECT COUNT(*) as cnt, COALESCE(SUM(outstanding_balance), 0) as total_outstanding FROM active_loans WHERE account_number=%s AND status='active'",
        (acc_num,),
        fetch="one"
    )

    loan_count = active_loans["cnt"] if active_loans else 0
    outstanding = float(active_loans["total_outstanding"]) if active_loans else 0

    # Log the FORCED closure with details
    log_tx(acc_num, "ADMIN_FORCE_CLOSE", balance,
           f"⚠️ FORCED closure by admin | Account: {account_holder} | Phone: {phone_number} | "
           f"Balance: ${balance:,.2f} | Active Loans: {loan_count} | Outstanding: ${outstanding:,.2f}")

    # Delete everything
    with get_db_transaction() as (conn, cur):
        if DB_TYPE == "mysql":
            cur.execute("DELETE FROM emi_payments WHERE loan_id IN (SELECT loan_id FROM active_loans WHERE account_number=%s)", (acc_num,))
            cur.execute("DELETE FROM active_loans WHERE account_number=%s", (acc_num,))
            cur.execute("DELETE FROM loan_applications WHERE account_number=%s", (acc_num,))
            cur.execute("DELETE FROM chat_messages WHERE session_token IN (SELECT session_token FROM chat_sessions WHERE account_number=%s)", (acc_num,))
            cur.execute("DELETE FROM chat_sessions WHERE account_number=%s", (acc_num,))
            cur.execute("DELETE FROM transaction_log WHERE account_ref=%s", (acc_num,))
            cur.execute("DELETE FROM accounts WHERE account_number=%s", (acc_num,))
        else:
            cur.execute("DELETE FROM emi_payments WHERE loan_id IN (SELECT loan_id FROM active_loans WHERE account_number=?)", (acc_num,))
            cur.execute("DELETE FROM active_loans WHERE account_number=?", (acc_num,))
            cur.execute("DELETE FROM loan_applications WHERE account_number=?", (acc_num,))
            cur.execute("DELETE FROM chat_messages WHERE session_token IN (SELECT session_token FROM chat_sessions WHERE account_number=?)", (acc_num,))
            cur.execute("DELETE FROM chat_sessions WHERE account_number=?", (acc_num,))
            cur.execute("DELETE FROM transaction_log WHERE account_ref=?", (acc_num,))
            cur.execute("DELETE FROM accounts WHERE account_number=?", (acc_num,))

    flash(f"⚠️ Account {fmt_acc(acc_num)} FORCE CLOSED | User: {account_holder} | "
          f"Balance Written Off: ${balance:,.2f} | Loans Cancelled: {loan_count} (${outstanding:,.2f})", "warning")

    return redirect(url_for("admin_dashboard"))


# ═══════════════════════════════════════════════════════════════
#  ADMIN: ANALYTICS & DASHBOARD ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    """Main Analytics Dashboard"""
    return render_template("admin_analytics.html")


@app.route("/api/admin/dashboard-stats", methods=["GET"])
@admin_required
def api_dashboard_stats():
    """
    Get comprehensive dashboard statistics
    Returns: JSON with all key metrics
    """

    # ========== ACCOUNT STATISTICS ==========
    account_stats = q_safe("""
        SELECT
            COUNT(*) as total_accounts,
            SUM(CASE WHEN account_type='SavingsAccount' THEN 1 ELSE 0 END) as savings_count,
            SUM(CASE WHEN account_type='CheckingAccount' THEN 1 ELSE 0 END) as checking_count,
            SUM(CASE WHEN is_frozen=1 THEN 1 ELSE 0 END) as frozen_count,
            COALESCE(SUM(balance), 0) as total_balance,
            COALESCE(AVG(balance), 0) as avg_balance,
            COALESCE(AVG(cibil_score), 0) as avg_cibil
        FROM accounts
    """, fetch="one")

    # ========== TRANSACTION STATISTICS ==========
    # Today's transactions
    today_txns = q_safe("""
        SELECT
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE DATE(created_at) = CURDATE()
    """, fetch="one") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE DATE(created_at) = DATE('now')
    """, fetch="one")

    # This month's transactions
    month_txns = q_safe("""
        SELECT
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE YEAR(created_at) = YEAR(CURDATE())
        AND MONTH(created_at) = MONTH(CURDATE())
    """, fetch="one") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    """, fetch="one")

    # Transaction breakdown by type
    tx_breakdown = q_safe("""
        SELECT
            log_type,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE log_type IN ('DEPOSIT', 'DEPOSIT_APPROVED', 'WITHDRAW', 'TRANSFER_IN', 'TRANSFER_OUT')
        GROUP BY log_type
    """, fetch="all")

    # ========== LOAN STATISTICS ==========
    loan_stats = q_safe("""
        SELECT
            COUNT(*) as total_active_loans,
            COALESCE(SUM(principal_amount), 0) as total_disbursed,
            COALESCE(SUM(outstanding_balance), 0) as total_outstanding,
            COALESCE(AVG(interest_rate), 0) as avg_interest_rate
        FROM active_loans
        WHERE status = 'active'
    """, fetch="one")

    pending_loans = q_safe("""
        SELECT COUNT(*) as count
        FROM loan_applications
        WHERE status = 'pending'
    """, fetch="one")

    # ========== DEPOSIT REQUESTS ==========
    deposit_requests = q_safe("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
            COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END), 0) as pending_amount
        FROM deposit_requests
    """, fetch="one")

    # ========== RECENT ACTIVITY ==========
    recent_accounts = q_safe("""
        SELECT account_number, account_holder, created_at
        FROM accounts
        ORDER BY created_at DESC
        LIMIT 5
    """, fetch="all")

    recent_large_txns = q_safe("""
        SELECT account_ref, log_type, amount, created_at
        FROM transaction_log
        WHERE amount > 10000
        ORDER BY created_at DESC
        LIMIT 5
    """, fetch="all")

    # ========== GROWTH METRICS ==========
    # New accounts this month
    new_accounts_month = q_safe("""
        SELECT COUNT(*) as count
        FROM accounts
        WHERE YEAR(created_at) = YEAR(CURDATE())
        AND MONTH(created_at) = MONTH(CURDATE())
    """, fetch="one") if DB_TYPE == "mysql" else q_safe("""
        SELECT COUNT(*) as count
        FROM accounts
        WHERE strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')
    """, fetch="one")

    return jsonify({
        'success': True,
        'accounts': {
            'total': account_stats['total_accounts'],
            'savings': account_stats['savings_count'],
            'checking': account_stats['checking_count'],
            'frozen': account_stats['frozen_count'],
            'total_balance': float(account_stats['total_balance']),
            'avg_balance': float(account_stats['avg_balance']),
            'avg_cibil': float(account_stats['avg_cibil']),
            'new_this_month': new_accounts_month['count']
        },
        'transactions': {
            'today_count': today_txns['count'],
            'today_volume': float(today_txns['total']),
            'month_count': month_txns['count'],
            'month_volume': float(month_txns['total']),
            'breakdown': [
                {
                    'type': tx['log_type'],
                    'count': tx['count'],
                    'total': float(tx['total'])
                } for tx in tx_breakdown
            ]
        },
        'loans': {
            'active_count': loan_stats['total_active_loans'],
            'total_disbursed': float(loan_stats['total_disbursed']),
            'total_outstanding': float(loan_stats['total_outstanding']),
            'avg_interest_rate': float(loan_stats['avg_interest_rate']) * 100,
            'pending_applications': pending_loans['count']
        },
        'deposit_requests': {
            'total': deposit_requests['total'],
            'pending': deposit_requests['pending'],
            'pending_amount': float(deposit_requests['pending_amount'])
        },
        'recent_activity': {
            'new_accounts': [
                {
                    'account_number': acc['account_number'],
                    'holder': acc['account_holder'],
                    'date': acc['created_at'].strftime('%Y-%m-%d %H:%M') if hasattr(acc['created_at'], 'strftime') else str(acc['created_at'])
                } for acc in recent_accounts
            ],
            'large_transactions': [
                {
                    'account': tx['account_ref'],
                    'type': tx['log_type'],
                    'amount': float(tx['amount']),
                    'date': tx['created_at'].strftime('%Y-%m-%d %H:%M') if hasattr(tx['created_at'], 'strftime') else str(tx['created_at'])
                } for tx in recent_large_txns
            ]
        }
    })


@app.route("/api/admin/transaction-trends", methods=["GET"])
@admin_required
def api_transaction_trends():
    """
    Get transaction trends over time
    Returns: Last 30 days of transaction data
    """

    trends = q_safe("""
        SELECT
            DATE(created_at) as date,
            log_type,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        AND log_type IN ('DEPOSIT', 'DEPOSIT_APPROVED', 'WITHDRAW', 'TRANSFER_IN', 'TRANSFER_OUT')
        GROUP BY DATE(created_at), log_type
        ORDER BY date ASC
    """, fetch="all") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            DATE(created_at) as date,
            log_type,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE created_at >= date('now', '-30 days')
        AND log_type IN ('DEPOSIT', 'DEPOSIT_APPROVED', 'WITHDRAW', 'TRANSFER_IN', 'TRANSFER_OUT')
        GROUP BY DATE(created_at), log_type
        ORDER BY date ASC
    """, fetch="all")

    return jsonify({
        'success': True,
        'trends': [
            {
                'date': str(t['date']),
                'type': t['log_type'],
                'count': t['count'],
                'total': float(t['total'])
            } for t in trends
        ]
    })


@app.route("/api/admin/cibil-distribution", methods=["GET"])
@admin_required
def api_cibil_distribution():
    """Get CIBIL score distribution"""

    distribution = q_safe("""
        SELECT
            CASE
                WHEN cibil_score >= 800 THEN 'Excellent (800+)'
                WHEN cibil_score >= 750 THEN 'Very Good (750-799)'
                WHEN cibil_score >= 700 THEN 'Good (700-749)'
                WHEN cibil_score >= 650 THEN 'Fair (650-699)'
                WHEN cibil_score >= 600 THEN 'Poor (600-649)'
                ELSE 'Very Poor (<600)'
            END as category,
            COUNT(*) as count
        FROM accounts
        GROUP BY category
        ORDER BY MIN(cibil_score) DESC
    """, fetch="all")

    return jsonify({
        'success': True,
        'distribution': [
            {'category': d['category'], 'count': d['count']}
            for d in distribution
        ]
    })


@app.route("/api/admin/top-accounts", methods=["GET"])
@admin_required
def api_top_accounts():
    """Get top accounts by balance"""

    top_accounts = q_safe("""
        SELECT
            account_number,
            account_holder,
            balance,
            cibil_score,
            account_type
        FROM accounts
        ORDER BY balance DESC
        LIMIT 10
    """, fetch="all")

    return jsonify({
        'success': True,
        'accounts': [
            {
                'account_number': acc['account_number'],
                'holder': acc['account_holder'],
                'balance': float(acc['balance']),
                'cibil': acc['cibil_score'],
                'type': acc['account_type']
            } for acc in top_accounts
        ]
    })


@app.route("/api/admin/loan-performance", methods=["GET"])
@admin_required
def api_loan_performance():
    """Get loan performance metrics"""

    # Loan status breakdown
    loan_status = q_safe("""
        SELECT
            status,
            COUNT(*) as count,
            COALESCE(SUM(outstanding_balance), 0) as total_outstanding
        FROM active_loans
        GROUP BY status
    """, fetch="all")

    # EMI payment performance
    emi_performance = q_safe("""
        SELECT
            YEAR(payment_date) as year,
            MONTH(payment_date) as month,
            COUNT(*) as payments_count,
            COALESCE(SUM(amount_paid), 0) as total_collected
        FROM emi_payments
        WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY YEAR(payment_date), MONTH(payment_date)
        ORDER BY year, month
    """, fetch="all") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            strftime('%Y', payment_date) as year,
            strftime('%m', payment_date) as month,
            COUNT(*) as payments_count,
            COALESCE(SUM(amount_paid), 0) as total_collected
        FROM emi_payments
        WHERE payment_date >= date('now', '-6 months')
        GROUP BY year, month
        ORDER BY year, month
    """, fetch="all")

    return jsonify({
        'success': True,
        'loan_status': [
            {
                'status': ls['status'],
                'count': ls['count'],
                'outstanding': float(ls['total_outstanding'])
            } for ls in loan_status
        ],
        'emi_performance': [
            {
                'period': f"{ep['year']}-{ep['month']}",
                'count': ep['payments_count'],
                'collected': float(ep['total_collected'])
            } for ep in emi_performance
        ]
    })


@app.route("/api/admin/hourly-activity", methods=["GET"])
@admin_required
def api_hourly_activity():
    """Get transaction activity by hour of day"""

    hourly = q_safe("""
        SELECT
            HOUR(created_at) as hour,
            COUNT(*) as count
        FROM transaction_log
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY HOUR(created_at)
        ORDER BY hour
    """, fetch="all") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            CAST(strftime('%H', created_at) AS INTEGER) as hour,
            COUNT(*) as count
        FROM transaction_log
        WHERE created_at >= date('now', '-7 days')
        GROUP BY hour
        ORDER BY hour
    """, fetch="all")

    return jsonify({
        'success': True,
        'hourly': [
            {'hour': h['hour'], 'count': h['count']}
            for h in hourly
        ]
    })


# ═══════════════════════════════════════════════════════════════
#  COMPREHENSIVE ANALYTICS API - REAL DATA INSIGHTS
# ═══════════════════════════════════════════════════════════════

@app.route("/api/admin/analytics/overview", methods=["GET"])
@admin_required
def api_analytics_overview():
    """
    Main dashboard overview with key metrics
    """

    # ========== ACCOUNT METRICS ==========
    account_stats = q_safe("""
        SELECT
            COUNT(*) as total_accounts,
            SUM(CASE WHEN account_type='SavingsAccount' THEN 1 ELSE 0 END) as savings,
            SUM(CASE WHEN account_type='CheckingAccount' THEN 1 ELSE 0 END) as checking,
            SUM(CASE WHEN is_frozen=1 THEN 1 ELSE 0 END) as frozen,
            COALESCE(SUM(balance), 0) as total_balance,
            COALESCE(AVG(balance), 0) as avg_balance,
            COALESCE(MAX(balance), 0) as max_balance,
            COALESCE(MIN(balance), 0) as min_balance,
            COALESCE(AVG(cibil_score), 0) as avg_cibil,
            SUM(CASE WHEN cibil_score >= 750 THEN 1 ELSE 0 END) as excellent_cibil,
            SUM(CASE WHEN cibil_score >= 600 AND cibil_score < 750 THEN 1 ELSE 0 END) as good_cibil,
            SUM(CASE WHEN cibil_score < 600 THEN 1 ELSE 0 END) as poor_cibil
        FROM accounts
    """, fetch="one")

    # ========== TRANSACTION VOLUME BY TYPE ==========
    transaction_volume = q_safe("""
        SELECT
            log_type,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total_amount,
            COALESCE(AVG(amount), 0) as avg_amount,
            COALESCE(MAX(amount), 0) as max_amount
        FROM transaction_log
        WHERE log_type IN ('DEPOSIT', 'DEPOSIT_APPROVED', 'WITHDRAW', 'TRANSFER_OUT', 'TRANSFER_IN')
        GROUP BY log_type
    """, fetch="all")

    # ========== DAILY TRANSACTION TRENDS (Last 30 Days) ==========
    daily_trends = q_safe("""
        SELECT
            DATE(created_at) as date,
            COUNT(*) as transaction_count,
            COALESCE(SUM(CASE WHEN log_type IN ('DEPOSIT', 'DEPOSIT_APPROVED') THEN amount ELSE 0 END), 0) as deposits,
            COALESCE(SUM(CASE WHEN log_type = 'WITHDRAW' THEN amount ELSE 0 END), 0) as withdrawals,
            COALESCE(SUM(CASE WHEN log_type IN ('TRANSFER_OUT', 'TRANSFER_IN') THEN amount ELSE 0 END), 0) as transfers
        FROM transaction_log
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        GROUP BY DATE(created_at)
        ORDER BY date ASC
    """, fetch="all") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            DATE(created_at) as date,
            COUNT(*) as transaction_count,
            COALESCE(SUM(CASE WHEN log_type IN ('DEPOSIT', 'DEPOSIT_APPROVED') THEN amount ELSE 0 END), 0) as deposits,
            COALESCE(SUM(CASE WHEN log_type = 'WITHDRAW' THEN amount ELSE 0 END), 0) as withdrawals,
            COALESCE(SUM(CASE WHEN log_type IN ('TRANSFER_OUT', 'TRANSFER_IN') THEN amount ELSE 0 END), 0) as transfers
        FROM transaction_log
        WHERE created_at >= date('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date ASC
    """, fetch="all")

    # ========== DEPOSIT REQUESTS STATUS ==========
    deposit_stats = q_safe("""
        SELECT
            COUNT(*) as total_requests,
            SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected,
            COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END), 0) as pending_amount,
            COALESCE(SUM(CASE WHEN status='approved' THEN amount ELSE 0 END), 0) as approved_amount,
            COALESCE(AVG(CASE WHEN status='approved' THEN TIMESTAMPDIFF(MINUTE, requested_at, processed_at) ELSE NULL END), 0) as avg_approval_time_minutes
        FROM deposit_requests
    """, fetch="one") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            COUNT(*) as total_requests,
            SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected,
            COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END), 0) as pending_amount,
            COALESCE(SUM(CASE WHEN status='approved' THEN amount ELSE 0 END), 0) as approved_amount,
            0 as avg_approval_time_minutes
        FROM deposit_requests
    """, fetch="one")

    # ========== LOAN STATISTICS ==========
    loan_stats = q_safe("""
        SELECT
            COUNT(DISTINCT la.application_id) as total_applications,
            SUM(CASE WHEN la.status='pending' THEN 1 ELSE 0 END) as pending_applications,
            SUM(CASE WHEN la.status='approved' THEN 1 ELSE 0 END) as approved_applications,
            SUM(CASE WHEN la.status='rejected' THEN 1 ELSE 0 END) as rejected_applications,
            COUNT(DISTINCT al.loan_id) as active_loans,
            COALESCE(SUM(al.principal_amount), 0) as total_disbursed,
            COALESCE(SUM(al.outstanding_balance), 0) as total_outstanding,
            COALESCE(SUM(ep.amount_paid), 0) as total_collected,
            COUNT(ep.payment_id) as total_emis_paid
        FROM loan_applications la
        LEFT JOIN active_loans al ON la.application_id = al.application_id
        LEFT JOIN emi_payments ep ON al.loan_id = ep.loan_id
    """, fetch="one")

    # ========== CHAT SUPPORT METRICS ==========
    chat_stats = q_safe("""
        SELECT
            COUNT(DISTINCT cs.session_token) as total_sessions,
            SUM(CASE WHEN cs.status='bot' THEN 1 ELSE 0 END) as bot_sessions,
            SUM(CASE WHEN cs.status='active' OR cs.status='waiting' THEN 1 ELSE 0 END) as active_sessions,
            SUM(CASE WHEN cs.status='closed' THEN 1 ELSE 0 END) as closed_sessions,
            COUNT(cm.id) as total_messages,
            SUM(CASE WHEN cm.sender_type='customer' THEN 1 ELSE 0 END) as customer_messages,
            SUM(CASE WHEN cm.sender_type='agent' THEN 1 ELSE 0 END) as agent_messages
        FROM chat_sessions cs
        LEFT JOIN chat_messages cm ON cs.session_token = cm.session_token
    """, fetch="one")

    # ========== TOP ACTIVE ACCOUNTS ==========
    top_accounts = q_safe("""
        SELECT
            a.account_number,
            a.account_holder,
            a.balance,
            a.cibil_score,
            COUNT(t.id) as transaction_count,
            COALESCE(SUM(t.amount), 0) as total_volume
        FROM accounts a
        LEFT JOIN transaction_log t ON a.account_number = t.account_ref
        WHERE t.log_type IN ('DEPOSIT', 'WITHDRAW', 'TRANSFER_OUT')
        GROUP BY a.account_number, a.account_holder, a.balance, a.cibil_score
        ORDER BY transaction_count DESC
        LIMIT 5
    """, fetch="all")

    # ========== RECENT ACTIVITY ==========
    recent_activity = q_safe("""
        SELECT
            account_ref,
            log_type,
            amount,
            description,
            created_at
        FROM transaction_log
        ORDER BY created_at DESC
        LIMIT 10
    """, fetch="all")

    return jsonify({
        'success': True,
        'accounts': {
            'total': account_stats['total_accounts'],
            'savings': account_stats['savings'],
            'checking': account_stats['checking'],
            'frozen': account_stats['frozen'],
            'total_balance': float(account_stats['total_balance']),
            'avg_balance': float(account_stats['avg_balance']),
            'max_balance': float(account_stats['max_balance']),
            'min_balance': float(account_stats['min_balance']),
            'avg_cibil': float(account_stats['avg_cibil']),
            'cibil_distribution': {
                'excellent': account_stats['excellent_cibil'],
                'good': account_stats['good_cibil'],
                'poor': account_stats['poor_cibil']
            }
        },
        'transactions': {
            'volume_by_type': [
                {
                    'type': tx['log_type'],
                    'count': tx['count'],
                    'total': float(tx['total_amount']),
                    'average': float(tx['avg_amount']),
                    'max': float(tx['max_amount'])
                } for tx in transaction_volume
            ],
            'daily_trends': [
                {
                    'date': str(day['date']),
                    'count': day['transaction_count'],
                    'deposits': float(day['deposits']),
                    'withdrawals': float(day['withdrawals']),
                    'transfers': float(day['transfers'])
                } for day in daily_trends
            ]
        },
        'deposit_requests': {
            'total': deposit_stats['total_requests'],
            'pending': deposit_stats['pending'],
            'approved': deposit_stats['approved'],
            'rejected': deposit_stats['rejected'],
            'pending_amount': float(deposit_stats['pending_amount']),
            'approved_amount': float(deposit_stats['approved_amount']),
            'avg_approval_time_minutes': float(deposit_stats['avg_approval_time_minutes'])
        },
        'loans': {
            'total_applications': loan_stats['total_applications'],
            'pending': loan_stats['pending_applications'],
            'approved': loan_stats['approved_applications'],
            'rejected': loan_stats['rejected_applications'],
            'active_loans': loan_stats['active_loans'],
            'total_disbursed': float(loan_stats['total_disbursed']),
            'total_outstanding': float(loan_stats['total_outstanding']),
            'total_collected': float(loan_stats['total_collected']),
            'emis_paid': loan_stats['total_emis_paid']
        },
        'chat_support': {
            'total_sessions': chat_stats['total_sessions'],
            'bot_sessions': chat_stats['bot_sessions'],
            'active_sessions': chat_stats['active_sessions'],
            'closed_sessions': chat_stats['closed_sessions'],
            'total_messages': chat_stats['total_messages'],
            'customer_messages': chat_stats['customer_messages'],
            'agent_messages': chat_stats['agent_messages']
        },
        'top_accounts': [
            {
                'account_number': acc['account_number'],
                'holder': acc['account_holder'],
                'balance': float(acc['balance']),
                'cibil': acc['cibil_score'],
                'transaction_count': acc['transaction_count'],
                'total_volume': float(acc['total_volume'])
            } for acc in top_accounts
        ],
        'recent_activity': [
            {
                'account': act['account_ref'],
                'type': act['log_type'],
                'amount': float(act['amount']) if act['amount'] else 0,
                'description': act['description'],
                'time': act['created_at'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(act['created_at'], 'strftime') else str(act['created_at'])
            } for act in recent_activity
        ]
    })


@app.route("/api/admin/analytics/transaction-breakdown", methods=["GET"])
@admin_required
def api_transaction_breakdown():
    """
    Detailed transaction breakdown by type, time, and patterns
    """

    # ========== BY TRANSACTION TYPE ==========
    by_type = q_safe("""
        SELECT
            log_type,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total,
            COALESCE(AVG(amount), 0) as average,
            COALESCE(MIN(amount), 0) as min_amount,
            COALESCE(MAX(amount), 0) as max_amount
        FROM transaction_log
        WHERE amount > 0
        GROUP BY log_type
        ORDER BY total DESC
    """, fetch="all")

    # ========== BY HOUR OF DAY ==========
    by_hour = q_safe("""
        SELECT
            HOUR(created_at) as hour,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as volume
        FROM transaction_log
        WHERE amount > 0
        GROUP BY HOUR(created_at)
        ORDER BY hour
    """, fetch="all") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            CAST(strftime('%H', created_at) AS INTEGER) as hour,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as volume
        FROM transaction_log
        WHERE amount > 0
        GROUP BY hour
        ORDER BY hour
    """, fetch="all")

    # ========== BY DAY OF WEEK ==========
    by_day = q_safe("""
        SELECT
            DAYOFWEEK(created_at) as day_num,
            DAYNAME(created_at) as day_name,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as volume
        FROM transaction_log
        WHERE amount > 0
        GROUP BY DAYOFWEEK(created_at), DAYNAME(created_at)
        ORDER BY day_num
    """, fetch="all") if DB_TYPE == "mysql" else q_safe("""
        SELECT
            CAST(strftime('%w', created_at) AS INTEGER) as day_num,
            CASE CAST(strftime('%w', created_at) AS INTEGER)
                WHEN 0 THEN 'Sunday'
                WHEN 1 THEN 'Monday'
                WHEN 2 THEN 'Tuesday'
                WHEN 3 THEN 'Wednesday'
                WHEN 4 THEN 'Thursday'
                WHEN 5 THEN 'Friday'
                WHEN 6 THEN 'Saturday'
            END as day_name,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as volume
        FROM transaction_log
        WHERE amount > 0
        GROUP BY day_num
        ORDER BY day_num
    """, fetch="all")

    # ========== AMOUNT RANGES ==========
    amount_ranges = q_safe("""
        SELECT
            CASE
                WHEN amount < 100 THEN '< $100'
                WHEN amount >= 100 AND amount < 500 THEN '$100 - $500'
                WHEN amount >= 500 AND amount < 1000 THEN '$500 - $1,000'
                WHEN amount >= 1000 AND amount < 5000 THEN '$1,000 - $5,000'
                WHEN amount >= 5000 THEN '> $5,000'
            END as range_label,
            COUNT(*) as count,
            COALESCE(SUM(amount), 0) as total
        FROM transaction_log
        WHERE amount > 0
        GROUP BY range_label
        ORDER BY MIN(amount)
    """, fetch="all")

    return jsonify({
        'success': True,
        'by_type': [
            {
                'type': t['log_type'],
                'count': t['count'],
                'total': float(t['total']),
                'average': float(t['average']),
                'min': float(t['min_amount']),
                'max': float(t['max_amount'])
            } for t in by_type
        ],
        'by_hour': [
            {
                'hour': h['hour'],
                'count': h['count'],
                'volume': float(h['volume'])
            } for h in by_hour
        ],
        'by_day': [
            {
                'day': d['day_name'],
                'count': d['count'],
                'volume': float(d['volume'])
            } for d in by_day
        ],
        'by_amount_range': [
            {
                'range': r['range_label'],
                'count': r['count'],
                'total': float(r['total'])
            } for r in amount_ranges
        ]
    })


@app.route("/api/admin/analytics/user-behavior", methods=["GET"])
@admin_required
def api_user_behavior():
    """
    User behavior patterns and engagement metrics
    """

    # ========== ACCOUNT ACTIVITY LEVELS ==========
    activity_levels = q_safe("""
        SELECT
            a.account_number,
            a.account_holder,
            a.created_at as account_age,
            COUNT(t.id) as transaction_count,
            COALESCE(SUM(t.amount), 0) as total_volume,
            MAX(t.created_at) as last_activity,
            CASE
                WHEN COUNT(t.id) >= 10 THEN 'High Activity'
                WHEN COUNT(t.id) >= 5 THEN 'Medium Activity'
                WHEN COUNT(t.id) >= 1 THEN 'Low Activity'
                ELSE 'Inactive'
            END as activity_level
        FROM accounts a
        LEFT JOIN transaction_log t ON a.account_number = t.account_ref
        GROUP BY a.account_number, a.account_holder, a.created_at
        ORDER BY transaction_count DESC
    """, fetch="all")

    # ========== CIBIL SCORE CHANGES ==========
    cibil_changes = q_safe("""
        SELECT
            account_ref,
            description,
            created_at
        FROM transaction_log
        WHERE description LIKE '%CIBIL%'
        ORDER BY created_at DESC
        LIMIT 20
    """, fetch="all")

    return jsonify({
        'success': True,
        'activity_levels': [
            {
                'account': act['account_number'],
                'holder': act['account_holder'],
                'transactions': act['transaction_count'],
                'volume': float(act['total_volume']),
                'level': act['activity_level'],
                'last_active': act['last_activity'].strftime('%Y-%m-%d') if act['last_activity'] and hasattr(act['last_activity'], 'strftime') else 'Never'
            } for act in activity_levels
        ],
        'recent_cibil_changes': [
            {
                'account': change['account_ref'],
                'description': change['description'],
                'time': change['created_at'].strftime('%Y-%m-%d %H:%M') if hasattr(change['created_at'], 'strftime') else str(change['created_at'])
            } for change in cibil_changes
        ]
    })


@app.route("/admin/analytics-comprehensive")
@admin_required
def admin_analytics_comprehensive():
    return render_template("admin_analytics_comprehensive.html")


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  🏦  PyBank SECURE Edition  |  http://127.0.0.1:8443")
    print(f"  DB      : {DB_TYPE.upper()}")
    print(f"  Security: {'✓ Bcrypt' if BCRYPT_AVAILABLE else '⚠ SHA256 fallback'}")
    print(f"  Support : https://127.0.0.1:8443/admin/support")
    print(f"  Admin   : https://127.0.0.1:8443/admin")
    print("=" * 60)
    app.run(
        host='127.0.0.1',
        port=8443,
        debug=True
    )












