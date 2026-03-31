# 🔒 PyBank Security Guide: Race Conditions, PIN Security & SQL Injection

## Table of Contents
1. [Race Condition Vulnerabilities](#race-conditions)
2. [PIN Security (Plain Text → Hashing)](#pin-security)
3. [SQL Injection Prevention](#sql-injection)
4. [Implementation Steps](#implementation)
5. [Testing Security Fixes](#testing)

---

## ⚠️ Issue #1: Race Conditions {#race-conditions}

### The Problem

**Scenario:** Two users withdraw from the same account simultaneously:

```python
Time    Thread 1 (ATM 1)              Thread 2 (ATM 2)              Balance
────────────────────────────────────────────────────────────────────────────
0ms     Read balance: $1000           —                             $1000
1ms     —                             Read balance: $1000           $1000
2ms     Withdraw $800                 —                             $1000
3ms     Write balance: $200           —                             $200
4ms     —                             Withdraw $800                 $200
5ms     —                             Write balance: $200           $200
────────────────────────────────────────────────────────────────────────────
RESULT: $1600 withdrawn, balance = $200 → Lost $600! 💥
```

### Why It Happens

Current code:
```python
# Step 1: Read (not atomic with Step 2)
acc = q("SELECT balance FROM accounts WHERE account_number=%s", (acc_num,), fetch="one")

# Step 2: Check and update (another thread can modify balance between steps!)
if acc["balance"] >= amount:
    q("UPDATE accounts SET balance=balance-%s WHERE account_number=%s", 
      (amount, acc_num), commit=True)
```

**Problem:** Time gap between READ and WRITE allows race conditions.

### The Solution: Database Transactions + Row Locking

```python
with get_db_transaction() as (conn, cur):
    # SELECT ... FOR UPDATE locks the row immediately
    cur.execute("""
        SELECT balance FROM accounts 
        WHERE account_number=%s 
        FOR UPDATE
    """, (acc_num,))
    
    acc = cur.fetchone()
    
    # Row is LOCKED - no other transaction can read/write it
    if acc["balance"] >= amount:
        cur.execute("""
            UPDATE accounts SET balance=%s 
            WHERE account_number=%s
        """, (acc["balance"] - amount, acc_num))
    
    # COMMIT releases lock - changes are atomic
```

**How it works:**
1. `FOR UPDATE` acquires exclusive lock on the row
2. Other transactions trying to access same row WAIT
3. All operations happen atomically
4. Lock released on COMMIT/ROLLBACK

### MySQL Isolation Levels

```sql
-- Default (good for most cases)
READ COMMITTED: See only committed data, prevents dirty reads

-- Higher consistency (slower, better for critical operations)
REPEATABLE READ: Same data throughout transaction (MySQL default)
SERIALIZABLE: Strongest isolation, slowest (full table locks)

-- Lower consistency (faster, risky)
READ UNCOMMITTED: See uncommitted changes (avoid!)
```

### Real-World Attack Example

**Attack:** High-frequency trading bot exploits race condition:
```python
# Attacker spawns 100 threads
import threading

def exploit():
    while True:
        withdraw_request(account="123456", amount=100)

threads = [threading.Thread(target=exploit) for _ in range(100)]
for t in threads: t.start()

# Without locking: 90%+ requests succeed even with $100 balance
# With locking: Only 1 succeeds, rest get "Insufficient funds"
```

---

## 🔐 Issue #2: PIN Security (Plain Text Storage) {#pin-security}

### Current Code (INSECURE)

```python
# Registration
pin = request.form.get("pin")  # "1234"
q("INSERT INTO accounts(..., pin) VALUES(..., %s)", (..., pin, ...))
# Database: pin = "1234"  ← Plain text! 💥

# Login
stored_pin = acc["pin"]  # "1234"
if entered_pin == stored_pin:  # Direct comparison
    login_success()
```

### Why This Is Terrible

1. **Database breach = all PINs exposed**
   - Attacker gets database dump → sees all PINs
   - Can log into any account immediately

2. **Insider threat**
   - DBAs, developers, support staff can see PINs
   - Violates principle of least privilege

3. **Compliance violation**
   - PCI DSS, GDPR, etc. REQUIRE cryptographic hashing
   - Legal liability if breached

### The Solution: Bcrypt Hashing

```python
import bcrypt

# Registration
def hash_pin(pin: str) -> str:
    salt = bcrypt.gensalt(rounds=12)  # Cost factor 12 = 2^12 iterations
    return bcrypt.hashpw(pin.encode(), salt).decode()

pin = request.form.get("pin")  # "1234"
hashed = hash_pin(pin)  # "$2b$12$xyz...abc" ← 60 chars, includes salt
q("INSERT INTO accounts(..., pin) VALUES(..., %s)", (..., hashed, ...))

# Login
def verify_pin(entered: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(entered.encode(), stored_hash.encode())

if verify_pin(entered_pin, acc["pin"]):
    login_success()
```

### Why Bcrypt?

**✓ Adaptive cost** — Increase rounds as computers get faster
**✓ Built-in salt** — Unique hash even for same PIN
**✓ Timing-safe** — Prevents timing attacks
**✓ Industry standard** — Used by GitHub, Reddit, etc.

### Hash Examples

```
PIN: 1234

Plain text:     1234
MD5 (bad):      81dc9bdb52d04dc20036dbd8313ed055
SHA256 (bad):   03ac674216f3e15c761ee1a5e255f067...
Bcrypt (good):  $2b$12$LQv3c1yqBWVHxkd0LHAkCOem...

Why MD5/SHA256 are bad:
- Too fast → brute force easy (billions/second on GPU)
- No salt → rainbow table attacks
- Not designed for passwords

Bcrypt:
- Slow by design → only ~100 hashes/second
- Built-in random salt
- Purpose-built for password hashing
```

### Migration Strategy (Production)

```python
def verify_pin_with_migration(pin: str, stored: str, account_id: str):
    """Gradually migrate from plain text to bcrypt"""
    
    # Check if already hashed (bcrypt starts with $2b$)
    if stored.startswith("$2b$"):
        return bcrypt.checkpw(pin.encode(), stored.encode())
    
    # Legacy plain text comparison
    if pin == stored:
        # Valid login! Hash and update NOW
        hashed = hash_pin(pin)
        q("UPDATE accounts SET pin=%s WHERE id=%s", (hashed, account_id))
        return True
    
    return False
```

---

## 💉 Issue #3: SQL Injection Prevention {#sql-injection}

### Good News: Already Prevented! ✅

Your current code uses **parameterized queries**, which are safe:

```python
# ✅ SAFE - Parameterized query
acc_num = request.form.get("account_number")
q("SELECT * FROM accounts WHERE account_number=%s", (acc_num,))

# How it works internally:
# 1. SQL statement sent to DB: "SELECT * FROM accounts WHERE account_number=?"
# 2. Parameter sent separately: "123456789012"
# 3. DB driver escapes and binds parameter
# 4. No way for user input to alter SQL structure
```

### How SQL Injection Works (Demo)

```python
# ❌ VULNERABLE CODE (string concatenation)
acc_num = request.form.get("account_number")
query = f"SELECT * FROM accounts WHERE account_number='{acc_num}'"
cur.execute(query)

# Normal input:
acc_num = "123456789012"
→ SELECT * FROM accounts WHERE account_number='123456789012'
✓ Returns 1 account

# Malicious input:
acc_num = "123' OR '1'='1"
→ SELECT * FROM accounts WHERE account_number='123' OR '1'='1'
✓ Returns ALL accounts! 💥

# Worse:
acc_num = "123'; DROP TABLE accounts; --"
→ SELECT * FROM accounts WHERE account_number='123'; DROP TABLE accounts; --'
✓ Deletes entire table! 💀
```

### Real Attack Examples

**1. Authentication bypass:**
```python
# Vulnerable login
username = request.form["username"]  # admin' OR '1'='1
password = request.form["password"]  # anything
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
# Becomes: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'
# → Logs in as admin without password!
```

**2. Data exfiltration:**
```python
# Attacker input: 123' UNION SELECT pin, NULL FROM accounts WHERE '1'='1
# Returns: all account PINs in result set
```

**3. Blind SQL injection:**
```python
# Even if results hidden, attacker can extract data:
acc_num = "123' AND (SELECT SUBSTRING(pin,1,1) FROM accounts WHERE id=1)='1' --"
# If page loads differently = first digit of PIN is '1'
# Repeat for each digit → extract entire PIN
```

### Defense: ALWAYS Use Parameterized Queries

```python
# ✅ Python (psycopg2, pymysql, sqlite3)
cur.execute("SELECT * FROM accounts WHERE account_number=%s", (acc_num,))

# ✅ Node.js (pg, mysql2)
db.query("SELECT * FROM accounts WHERE account_number=$1", [acc_num])

# ✅ Java (JDBC)
stmt = conn.prepareStatement("SELECT * FROM accounts WHERE account_number=?");
stmt.setString(1, acc_num);

# ✅ C# (ADO.NET)
cmd.CommandText = "SELECT * FROM accounts WHERE account_number=@acc";
cmd.Parameters.AddWithValue("@acc", acc_num);
```

### Why Parameterized Queries Work

```
┌─────────────────────────────────────────────────────────┐
│  Application Layer                                      │
│  ────────────────────────────────────────────────────  │
│  user_input = "123' OR '1'='1"                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         Sends TWO separate pieces:
         1. SQL: "SELECT * WHERE id=?"
         2. Param: ["123' OR '1'='1"]
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Database Driver Layer                                  │
│  ────────────────────────────────────────────────────  │
│  • Escapes special chars: ' → \'                       │
│  • Wraps in quotes: "123\' OR \'1\'=\'1\'"            │
│  • Treats as LITERAL STRING, not SQL code              │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Database Engine                                        │
│  ────────────────────────────────────────────────────  │
│  SELECT * FROM accounts WHERE id='123\' OR \'1\'=\'1\''│
│  → Searches for account literally named "123' OR..."   │
│  → Finds nothing (safe!)                                │
└─────────────────────────────────────────────────────────┘
```

### Additional SQL Injection Defenses

```python
# 1. Input validation (defense in depth)
import re

def validate_account_number(acc_num: str) -> bool:
    # Only allow 12 digits
    return bool(re.match(r'^\d{12}$', acc_num))

if not validate_account_number(acc_num):
    return error("Invalid account number format")

# 2. Whitelist allowed characters
def sanitize_input(text: str) -> str:
    # Only allow alphanumeric + space
    return re.sub(r'[^a-zA-Z0-9 ]', '', text)

# 3. Limit permissions
# Database user should have minimum privileges:
GRANT SELECT, INSERT, UPDATE ON accounts TO app_user;
-- NO DELETE, DROP, ALTER permissions

# 4. Web Application Firewall (WAF)
# Block common SQL injection patterns:
# - UNION SELECT
# - OR 1=1
# - ; DROP TABLE
```

---

## 🚀 Implementation Steps {#implementation}

### Step 1: Install Security Dependencies

```bash
pip install bcrypt==4.0.1
# Or for production: pip install argon2-cffi  (even better than bcrypt)
```

### Step 2: Update Database Schema

```sql
-- Widen PIN column to store bcrypt hash (60 chars)
ALTER TABLE accounts MODIFY COLUMN pin VARCHAR(255);

-- Add index for better performance
CREATE INDEX idx_account_number ON accounts(account_number);

-- Add transaction isolation level
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
```

### Step 3: Replace Database Layer

```python
# Replace old q() function with db_secure.py functions

# Before:
acc = q("SELECT * FROM accounts WHERE account_number=%s", (acc_num,), fetch="one")

# After:
acc = q_safe("SELECT * FROM accounts WHERE account_number=%s", (acc_num,), fetch="one")

# For writes - use transactions:
with get_db_transaction() as (conn, cur):
    cur.execute("UPDATE accounts SET balance=%s WHERE account_number=%s FOR UPDATE",
                (new_balance, acc_num))
```

### Step 4: Update Registration Endpoint

```python
from db_secure import hash_pin

@app.route("/register", methods=["POST"])
def register():
    pin = request.form.get("pin")
    
    # Hash PIN before storing
    pin_hashed = hash_pin(pin)
    
    q("INSERT INTO accounts(..., pin) VALUES(..., %s)",
      (..., pin_hashed, ...), commit=True)
```

### Step 5: Update Login Endpoint

```python
from db_secure import verify_pin

@app.route("/login", methods=["POST"])
def login():
    entered_pin = request.form.get("pin")
    acc = q_safe("SELECT * FROM accounts WHERE account_number=%s", (acc_num,), fetch="one")
    
    if not acc:
        flash("Account not found")
        return render_template("login.html")
    
    # Verify hashed PIN
    if not verify_pin(entered_pin, acc["pin"]):
        flash("Incorrect PIN")
        return render_template("login.html")
    
    session["acc_num"] = acc_num
    return redirect(url_for("dashboard"))
```

### Step 6: Update Transaction Endpoints

```python
from db_secure import secure_withdraw, secure_transfer

@app.route("/withdraw", methods=["POST"])
@login_required
def withdraw():
    amount = float(request.form["amount"])
    
    # Use atomic transaction
    success, msg = secure_withdraw(session["acc_num"], amount)
    
    if success:
        update_cibil(session["acc_num"], -10)
        log_tx(session["acc_num"], "WITHDRAW", amount, "Withdrawal")
        flash(f"${amount:,.2f} withdrawn successfully!", "success")
    else:
        flash(msg, "error")
    
    return redirect(url_for("dashboard"))


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    receiver_phone = request.form.get("phone")
    amount = float(request.form["amount"])
    
    receiver = q_safe("SELECT account_number FROM accounts WHERE phone_number=%s",
                      (receiver_phone,), fetch="one")
    
    if not receiver:
        flash("Recipient not found", "error")
        return redirect(url_for("transfer"))
    
    # Atomic P2P transfer
    success, msg = secure_transfer(session["acc_num"], receiver["account_number"], amount)
    
    if success:
        flash(f"${amount:,.2f} sent successfully!", "success")
    else:
        flash(msg, "error")
    
    return redirect(url_for("dashboard"))
```

---

## 🧪 Testing Security Fixes {#testing}

### Test 1: Race Condition Protection

```python
import threading
import time

def concurrent_withdraw():
    """Simulate 10 simultaneous withdrawals"""
    threads = []
    for i in range(10):
        t = threading.Thread(target=lambda: withdraw_request(acc_num="123456", amount=100))
        threads.append(t)
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # Expected: Only 1 succeeds (if balance = $100)
    # Without locking: 8-10 succeed (FAIL)
    # With locking: 1 succeeds (PASS)

# Run test
concurrent_withdraw()
balance = get_balance("123456")
assert balance == 0, f"Race condition! Balance = {balance}"
```

### Test 2: PIN Hashing

```python
from db_secure import hash_pin, verify_pin

# Create account with hashed PIN
pin = "1234"
hashed = hash_pin(pin)
print(f"Plain: {pin}")
print(f"Hashed: {hashed}")
print(f"Length: {len(hashed)} chars")

# Verify correct PIN
assert verify_pin("1234", hashed) == True
print("✓ Correct PIN verified")

# Verify wrong PIN
assert verify_pin("9999", hashed) == False
print("✓ Wrong PIN rejected")

# Check hash is different each time (salt)
hash1 = hash_pin("1234")
hash2 = hash_pin("1234")
assert hash1 != hash2
print("✓ Unique salt per hash")

# Database breach simulation
print("\n[ATTACKER VIEW OF DATABASE]")
print(f"PIN column: {hashed}")
print("Cannot determine original PIN from hash!")
```

### Test 3: SQL Injection Prevention

```python
# Test malicious inputs
malicious_inputs = [
    "123' OR '1'='1",
    "123'; DROP TABLE accounts; --",
    "123' UNION SELECT pin FROM accounts WHERE '1'='1",
    "123' AND 1=1 --",
]

for payload in malicious_inputs:
    result = q_safe("SELECT * FROM accounts WHERE account_number=%s", (payload,), fetch="one")
    assert result is None, f"SQL injection succeeded with payload: {payload}"
    print(f"✓ Blocked: {payload}")

print("\n✅ All SQL injection attempts blocked!")
```

### Load Test (Apache Bench)

```bash
# Test concurrent load
ab -n 1000 -c 50 -p withdraw.json -T application/json \
   http://localhost:5000/withdraw

# Metrics to check:
# - Requests per second: Should remain stable
# - Failed requests: Should be 0
# - Data integrity: Balance should be mathematically correct
```

---

## 📊 Security Comparison

| Issue | Before | After | Risk Reduction |
|-------|--------|-------|----------------|
| **Race Conditions** | No locking, balance corruption possible | Row-level locking, atomic transactions | 100% |
| **PIN Security** | Plain text in database | Bcrypt hashed (cost 12) | 99.99% |
| **SQL Injection** | Already safe (parameterized queries) | Still safe | Already 100% |
| **Timing Attacks** | Vulnerable | Constant-time comparison | 100% |
| **Database Breach** | All PINs instantly compromised | Attacker gets useless hashes | 99.9% |

---

## 🎯 Production Checklist

- [ ] Install `bcrypt` or `argon2-cffi`
- [ ] Migrate all PINs to hashed format
- [ ] Replace all write operations with `get_db_transaction()`
- [ ] Add `FOR UPDATE` to all balance reads before updates
- [ ] Set database isolation level to `READ COMMITTED` or higher
- [ ] Add database connection pooling (e.g., `SQLAlchemy`)
- [ ] Enable SSL/TLS for database connections
- [ ] Implement rate limiting (e.g., `Flask-Limiter`)
- [ ] Add request logging and monitoring
- [ ] Set up database replication (read replicas)
- [ ] Configure automated backups
- [ ] Add 2FA for admin accounts
- [ ] Implement CSRF protection (`Flask-WTF`)
- [ ] Enable HTTPS (Let's Encrypt)
- [ ] Set security headers (CSP, HSTS, X-Frame-Options)
- [ ] Run penetration testing
- [ ] Set up intrusion detection (e.g., `fail2ban`)

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Bcrypt Docs](https://github.com/pyca/bcrypt)
- [MySQL Transactions](https://dev.mysql.com/doc/refman/8.0/en/innodb-locking.html)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
