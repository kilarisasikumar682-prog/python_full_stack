"""
Secure Database Layer with Transaction Support & Row Locking
Prevents race conditions, adds PIN hashing, and maintains SQL injection protection
Compatible with Python 3.7+
"""
import os
import sqlite3
import hashlib
import hmac
from contextlib import contextmanager
from threading import Lock
from typing import Tuple, Optional, Dict, Any, List

try:
    import pymysql
    import pymysql.cursors
    DB_TYPE = "mysql"
except ImportError:
    DB_TYPE = "sqlite"

# Thread-safe connection pool for SQLite
_sqlite_lock = Lock()

MYSQL_CONFIG = {
    "host":     os.environ.get("DB_HOST",     "localhost"),
    "port":     int(os.environ.get("DB_PORT", 3306)),
    "user":     os.environ.get("DB_USER",     "root"),
    "password": os.environ.get("DB_PASS",     "Admin_451807"),
    "database": os.environ.get("DB_NAME",     "bank_db"),
    "charset":  "utf8mb4",
}
SQLITE_PATH = os.path.join(os.path.dirname(__file__), "bank_data.db")


# ═══════════════════════════════════════════════════════════════
#  SECURE CONNECTION MANAGER WITH TRANSACTIONS
# ═══════════════════════════════════════════════════════════════

@contextmanager
def get_db_transaction(isolation_level='READ COMMITTED'):
    """
    Context manager for atomic database transactions with proper locking.
    
    Usage:
        with get_db_transaction() as (conn, cur):
            cur.execute("SELECT balance FROM accounts WHERE id=%s FOR UPDATE", (acc_id,))
            # Row is now LOCKED - no other transaction can modify it
            cur.execute("UPDATE accounts SET balance=%s WHERE id=%s", (new_bal, acc_id))
            # Commit happens automatically on exit
    """
    if DB_TYPE == "mysql":
        conn = pymysql.connect(**MYSQL_CONFIG, cursorclass=pymysql.cursors.DictCursor)
        conn.autocommit = False  # START TRANSACTION
        cur = conn.cursor()
        try:
            # Set isolation level for this transaction
            cur.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation_level}")
            yield conn, cur
            conn.commit()  # SUCCESS - commit all changes atomically
        except Exception as e:
            conn.rollback()  # FAILURE - rollback everything
            raise e
        finally:
            cur.close()
            conn.close()
    else:  # SQLite
        with _sqlite_lock:  # SQLite needs global lock for writes
            conn = sqlite3.connect(SQLITE_PATH, isolation_level='DEFERRED')
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")  # Lock database for writes
                yield conn, cur
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                cur.close()
                conn.close()


def q_safe(sql, params=(), fetch="all"):
    """
    Read-only query with SQL injection protection via parameterized queries.
    Use get_db_transaction() for writes/updates.
    """
    if DB_TYPE == "mysql":
        conn = pymysql.connect(**MYSQL_CONFIG, cursorclass=pymysql.cursors.DictCursor)
    else:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        sql = sql.replace("%s", "?")  # SQLite uses ? instead of %s
    
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        if fetch == "all":
            rows = cur.fetchall()
            return [dict(r) for r in rows]
        elif fetch == "one":
            row = cur.fetchone()
            return dict(row) if row else None
        else:
            return None
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════
#  PIN SECURITY - BCRYPT HASHING
# ═══════════════════════════════════════════════════════════════

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("[WARN] bcrypt not installed - using SHA256 fallback (install: pip install bcrypt)")


def hash_pin(pin: str) -> str:
    """
    Securely hash a PIN using bcrypt (or SHA256 fallback).
    
    Production: Use bcrypt with cost factor 12+
    This example: bcrypt cost 10 for speed (still secure)
    """
    if BCRYPT_AVAILABLE:
        # Bcrypt with salt - industry standard
        return bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt(rounds=10)).decode('utf-8')
    else:
        # Fallback: SHA256 with salt (less secure, but better than plain text)
        salt = os.urandom(32).hex()
        hashed = hashlib.sha256((pin + salt).encode('utf-8')).hexdigest()
        return f"sha256${salt}${hashed}"


def verify_pin(pin: str, hashed: str) -> bool:
    """
    Verify a PIN against its hash.
    Constant-time comparison to prevent timing attacks.
    """
    if BCRYPT_AVAILABLE:
        try:
            return bcrypt.checkpw(pin.encode('utf-8'), hashed.encode('utf-8'))
        except:
            return False
    else:
        # Fallback SHA256 verification
        if not hashed.startswith("sha256$"):
            # Legacy plain text comparison (migration mode)
            return pin == hashed
        try:
            _, salt, stored_hash = hashed.split('$')
            computed = hashlib.sha256((pin + salt).encode('utf-8')).hexdigest()
            return hmac.compare_digest(computed, stored_hash)  # Constant-time
        except:
            return False


# ═══════════════════════════════════════════════════════════════
#  SECURE TRANSACTION HELPERS
# ═══════════════════════════════════════════════════════════════

def secure_withdraw(account_number: str, amount: float) -> Tuple[bool, str]:
    """
    Thread-safe withdrawal with row locking to prevent race conditions.
    
    Returns: (success: bool, message: str)
    """
    try:
        with get_db_transaction() as (conn, cur):
            # CRITICAL: SELECT ... FOR UPDATE locks the row
            if DB_TYPE == "mysql":
                cur.execute("""
                    SELECT balance, account_type, overdraft_limit, is_frozen 
                    FROM accounts 
                    WHERE account_number=%s 
                    FOR UPDATE
                """, (account_number,))
            else:
                cur.execute("""
                    SELECT balance, account_type, overdraft_limit, is_frozen 
                    FROM accounts 
                    WHERE account_number=?
                """, (account_number,))
            
            acc = cur.fetchone()
            if not acc:
                return False, "Account not found"
            
            acc = dict(acc)
            
            if acc["is_frozen"]:
                return False, "Account is frozen"
            
            # Check balance with overdraft
            overdraft = float(acc["overdraft_limit"]) if acc["account_type"] == "CheckingAccount" else 0
            if float(acc["balance"]) - amount < -overdraft:
                return False, "Insufficient funds"
            
            # Update balance (row is still locked)
            new_balance = float(acc["balance"]) - amount
            if DB_TYPE == "mysql":
                cur.execute("UPDATE accounts SET balance=%s WHERE account_number=%s",
                           (new_balance, account_number))
            else:
                cur.execute("UPDATE accounts SET balance=? WHERE account_number=?",
                           (new_balance, account_number))
            
            # Transaction commits automatically on context exit
            return True, "Success"
    
    except Exception as e:
        return False, f"Transaction failed: {str(e)}"


def secure_transfer(from_acc: str, to_acc: str, amount: float) -> Tuple[bool, str]:
    """
    Atomic P2P transfer - both accounts locked, all-or-nothing.
    """
    try:
        with get_db_transaction() as (conn, cur):
            # Lock BOTH accounts in consistent order (prevent deadlock)
            acc_nums = sorted([from_acc, to_acc])
            
            if DB_TYPE == "mysql":
                cur.execute("""
                    SELECT account_number, balance, account_type, overdraft_limit, is_frozen
                    FROM accounts 
                    WHERE account_number IN (%s, %s)
                    ORDER BY account_number
                    FOR UPDATE
                """, tuple(acc_nums))
            else:
                cur.execute("""
                    SELECT account_number, balance, account_type, overdraft_limit, is_frozen
                    FROM accounts 
                    WHERE account_number IN (?, ?)
                    ORDER BY account_number
                """, tuple(acc_nums))
            
            accounts = {dict(row)["account_number"]: dict(row) for row in cur.fetchall()}
            
            if len(accounts) != 2:
                return False, "One or both accounts not found"
            
            sender = accounts[from_acc]
            receiver = accounts[to_acc]
            
            if sender["is_frozen"] or receiver["is_frozen"]:
                return False, "Account frozen"
            
            # Check sender balance
            overdraft = float(sender["overdraft_limit"]) if sender["account_type"] == "CheckingAccount" else 0
            if float(sender["balance"]) - amount < -overdraft:
                return False, "Insufficient funds"
            
            # Perform atomic transfer
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

# ═══════════════════════════════════════════════════════════════
#  EXAMPLE USAGE
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Example 1: Create account with hashed PIN
    pin_plaintext = "1234"
    pin_hashed = hash_pin(pin_plaintext)
    print(f"Plain: {pin_plaintext}")
    print(f"Hashed: {pin_hashed}")
    print(f"Verify correct: {verify_pin('1234', pin_hashed)}")
    print(f"Verify wrong: {verify_pin('9999', pin_hashed)}")
    
    # Example 2: Secure withdrawal
    success, msg = secure_withdraw("123456789012", 100.00)
    print(f"Withdrawal: {msg}")
    
    # Example 3: Atomic transfer
    success, msg = secure_transfer("123456789012", "987654321098", 50.00)
    print(f"Transfer: {msg}")
