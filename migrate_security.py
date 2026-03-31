#!/usr/bin/env python3
"""
PyBank Security Migration Script
Upgrades existing database with security enhancements:
1. Hashes all plain text PINs → bcrypt
2. Adds missing indexes for performance
3. Validates data integrity
4. Creates backup before changes

Usage:
    python migrate_security.py --backup --verbose
"""

import sys
import os
import argparse
from datetime import datetime

# Import secure functions
try:
    from db_secure import hash_pin, get_db_transaction, q_safe, DB_TYPE
except ImportError:
    print("Error: db_secure.py not found. Make sure it's in the same directory.")
    sys.exit(1)

# Import database driver based on DB_TYPE
if DB_TYPE == "mysql":
    try:
        import pymysql
    except ImportError:
        print("Warning: pymysql not installed, using sqlite3")
        import sqlite3
else:
    import sqlite3

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    print("Warning: bcrypt not installed. Using SHA256 fallback.")
    print("Install: pip install bcrypt")
    BCRYPT_AVAILABLE = False


def create_backup(db_path=None):
    """Create database backup before migration"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if DB_TYPE == "sqlite":
        import shutil
        db_path = db_path or "bank_data.db"
        backup_path = f"bank_data_backup_{timestamp}.db"
        
        if os.path.exists(db_path):
            shutil.copy2(db_path, backup_path)
            print(f"✓ SQLite backup created: {backup_path}")
            return backup_path
        else:
            print(f"Warning: Database file {db_path} not found")
            return None
    else:
        print("✓ MySQL backup via mysqldump:")
        print(f"  mysqldump -u root -p bank_db > bank_db_backup_{timestamp}.sql")
        print("  Run this command manually before proceeding!")
        input("  Press Enter when backup is complete...")
        return f"bank_db_backup_{timestamp}.sql"


def validate_pin_format(pin_str):
    """Check if PIN is already hashed or plain text"""
    if not pin_str:
        return False, "empty"
    
    # Bcrypt hash format: $2b$XX$...  (60 chars)
    if pin_str.startswith("$2b$") and len(pin_str) == 60:
        return True, "bcrypt"
    
    # SHA256 fallback format: sha256$salt$hash
    if pin_str.startswith("sha256$"):
        return True, "sha256"
    
    # Assume plain text if 4-6 digits
    if len(pin_str) <= 10 and pin_str.isdigit():
        return False, "plaintext"
    
    return None, "unknown"


def migrate_pins(dry_run=False, verbose=False):
    """Hash all plain text PINs in database"""
    print("\n" + "="*60)
    print("STEP 1: PIN Migration (Plain Text → Bcrypt)")
    print("="*60)
    
    # Get all accounts
    accounts = q_safe("SELECT id, account_number, pin FROM accounts", fetch="all")
    
    if not accounts:
        print("No accounts found in database.")
        return
    
    total = len(accounts)
    needs_migration = 0
    already_hashed = 0
    errors = 0
    
    print(f"Found {total} accounts\n")
    
    for acc in accounts:
        acc_id = acc["id"]
        acc_num = acc["account_number"]
        current_pin = acc["pin"]
        
        is_hashed, pin_type = validate_pin_format(current_pin)
        
        if is_hashed:
            already_hashed += 1
            if verbose:
                print(f"  {acc_num}: Already hashed ({pin_type})")
            continue
        
        if pin_type == "unknown":
            errors += 1
            print(f"  ⚠️  {acc_num}: Unknown PIN format: {current_pin[:10]}...")
            continue
        
        needs_migration += 1
        
        if dry_run:
            print(f"  [DRY RUN] {acc_num}: Would hash PIN {current_pin} → (bcrypt)")
        else:
            try:
                hashed = hash_pin(current_pin)
                
                with get_db_transaction() as (conn, cur):
                    if DB_TYPE == "mysql":
                        cur.execute("UPDATE accounts SET pin=%s WHERE id=%s", (hashed, acc_id))
                    else:
                        cur.execute("UPDATE accounts SET pin=? WHERE id=?", (hashed, acc_id))
                
                if verbose:
                    print(f"  ✓ {acc_num}: PIN hashed successfully")
                else:
                    print(".", end="", flush=True)
                
            except Exception as e:
                errors += 1
                print(f"\n  ✗ {acc_num}: Error - {str(e)}")
    
    print("\n")
    print("─"*60)
    print(f"Total accounts:       {total}")
    print(f"Already hashed:       {already_hashed}")
    print(f"Migrated:             {needs_migration}")
    print(f"Errors:               {errors}")
    print("─"*60)
    
    if not dry_run and needs_migration > 0:
        print("✅ PIN migration completed!")
    elif dry_run:
        print("ℹ️  Dry run completed. No changes made.")


def add_indexes(dry_run=False):
    """Add performance indexes"""
    print("\n" + "="*60)
    print("STEP 2: Database Indexes")
    print("="*60)
    
    indexes = [
        ("idx_account_number", "accounts", "account_number"),
        ("idx_phone_number", "accounts", "phone_number"),
        ("idx_transaction_account", "transaction_log", "account_ref"),
        ("idx_loan_account", "loan_applications", "account_number"),
    ]
    
    for idx_name, table, column in indexes:
        try:
            if dry_run:
                print(f"  [DRY RUN] Would create index {idx_name} on {table}({column})")
            else:
                with get_db_transaction() as (conn, cur):
                    if DB_TYPE == "mysql":
                        cur.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table}({column})")
                    else:
                        cur.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table}({column})")
                print(f"  ✓ Created index {idx_name}")
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                print(f"  • Index {idx_name} already exists")
            else:
                print(f"  ✗ Error creating {idx_name}: {e}")
    
    print("─"*60)


def validate_data_integrity():
    """Check for data anomalies"""
    print("\n" + "="*60)
    print("STEP 3: Data Integrity Validation")
    print("="*60)
    
    checks = []
    
    # Check 1: Duplicate account numbers
    dup = q_safe("""
        SELECT account_number, COUNT(*) as cnt 
        FROM accounts 
        GROUP BY account_number 
        HAVING cnt > 1
    """, fetch="all")
    
    if dup:
        checks.append(f"⚠️  Found {len(dup)} duplicate account numbers")
    else:
        checks.append("✓ No duplicate account numbers")
    
    # Check 2: Duplicate phone numbers
    dup_phone = q_safe("""
        SELECT phone_number, COUNT(*) as cnt 
        FROM accounts 
        GROUP BY phone_number 
        HAVING cnt > 1
    """, fetch="all")
    
    if dup_phone:
        checks.append(f"⚠️  Found {len(dup_phone)} duplicate phone numbers")
    else:
        checks.append("✓ No duplicate phone numbers")
    
    # Check 3: Invalid balances
    invalid_bal = q_safe("""
        SELECT COUNT(*) as cnt 
        FROM accounts 
        WHERE balance < -overdraft_limit - 1
    """, fetch="one")
    
    if invalid_bal and invalid_bal["cnt"] > 0:
        checks.append(f"⚠️  Found {invalid_bal['cnt']} accounts with invalid overdraft")
    else:
        checks.append("✓ All balances within overdraft limits")
    
    # Check 4: Orphaned transactions
    orphaned = q_safe("""
        SELECT COUNT(*) as cnt 
        FROM transaction_log tl 
        LEFT JOIN accounts a ON tl.account_ref = a.account_number 
        WHERE a.account_number IS NULL
    """, fetch="one")
    
    if orphaned and orphaned["cnt"] > 0:
        checks.append(f"⚠️  Found {orphaned['cnt']} orphaned transactions")
    else:
        checks.append("✓ No orphaned transactions")
    
    for check in checks:
        print(f"  {check}")
    
    print("─"*60)


def show_statistics():
    """Display database statistics"""
    print("\n" + "="*60)
    print("Database Statistics")
    print("="*60)
    
    sql = """
        SELECT 
            COUNT(*) as total_accounts,
            SUM(CASE WHEN pin LIKE '$2b$%' THEN 1 ELSE 0 END) as bcrypt_pins,
            SUM(CASE WHEN pin LIKE 'sha256$%' THEN 1 ELSE 0 END) as sha256_pins,
            SUM(CASE WHEN pin NOT LIKE '$2b$%' AND pin NOT LIKE 'sha256$%' THEN 1 ELSE 0 END) as plaintext_pins
        FROM accounts
    """
    
    # Escape '%' as '%%' for PyMySQL, leave as '%' for SQLite
    if DB_TYPE == "mysql":
        sql = sql.replace("%", "%%")
        
    stats = q_safe(sql, fetch="one")
    
    # ... rest of the function remains the same


def main():
    parser = argparse.ArgumentParser(description="PyBank Security Migration")
    parser.add_argument("--backup", action="store_true", help="Create database backup")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--skip-pins", action="store_true", help="Skip PIN migration")
    parser.add_argument("--skip-indexes", action="store_true", help="Skip index creation")
    
    args = parser.parse_args()
    
    print("╔" + "═"*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "  PyBank Security Migration Tool".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "═"*58 + "╝")
    
    if args.dry_run:
        print("\n🔍 DRY RUN MODE - No changes will be made\n")
    
    # Backup
    if args.backup and not args.dry_run:
        create_backup()
    
    # Statistics before
    show_statistics()
    
    # Migrate PINs
    if not args.skip_pins:
        migrate_pins(dry_run=args.dry_run, verbose=args.verbose)
    
    # Add indexes
    if not args.skip_indexes:
        add_indexes(dry_run=args.dry_run)
    
    # Validate integrity
    validate_data_integrity()
    
    # Statistics after
    if not args.dry_run:
        show_statistics()
    
    print("\n" + "="*60)
    if args.dry_run:
        print("✓ Dry run completed. Run without --dry-run to apply changes.")
    else:
        print("✅ Migration completed successfully!")
        print("\nNext steps:")
        print("  1. Update app.py to use db_secure.py functions")
        print("  2. Test login with existing accounts")
        print("  3. Monitor logs for any issues")
        print("  4. Deploy to production")
    print("="*60 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Migration interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
