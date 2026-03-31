#!/usr/bin/env python3
"""
PyBank Bug Fix Script
Automatically fixes the line 102 bug in app_secure.py

Usage: python fix_bug.py app_secure.py
"""

import sys
import os
import shutil
from datetime import datetime

def fix_line_102(filename):
    """Fix the bug on line 102"""
    
    # Check if file exists
    if not os.path.exists(filename):
        print(f"❌ Error: File '{filename}' not found!")
        return False
    
    # Create backup
    backup_name = f"{filename}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(filename, backup_name)
    print(f"✓ Backup created: {backup_name}")
    
    # Read the file
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Check if bug exists
    bug_found = False
    fixed = False
    
    for i, line in enumerate(lines, 1):
        if "os.environ.get('Admin_451807')" in line or 'os.environ.get("Admin_451807")' in line:
            print(f"✓ Bug found on line {i}")
            bug_found = True
            
            # Fix the line
            if "DB_PASS" in line:
                # Replace the buggy part
                lines[i-1] = line.replace(
                    "os.environ.get('Admin_451807')",
                    "os.environ.get('DB_PASS')"
                ).replace(
                    'os.environ.get("Admin_451807")',
                    "os.environ.get('DB_PASS')"
                )
                print(f"✓ Fixed line {i}")
                fixed = True
    
    if not bug_found:
        print("✓ No bug found - file may already be fixed!")
        print("  Looking for: os.environ.get('Admin_451807')")
        
        # Check if it's already fixed
        for i, line in enumerate(lines, 1):
            if "DB_PASS = os.environ.get('DB_PASS')" in line or 'DB_PASS = os.environ.get("DB_PASS")' in line:
                print(f"✓ Line {i} already uses correct env var name: DB_PASS")
                return True
        
        return False
    
    if fixed:
        # Write the fixed file
        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        print(f"\n🎉 SUCCESS! Bug fixed in {filename}")
        print(f"\nBackup saved as: {backup_name}")
        print(f"\n📝 Next steps:")
        print(f"1. Set environment variable:")
        print(f"   Windows:  $env:DB_PASS = \"Admin_451807\"")
        print(f"   Linux:    export DB_PASS=\"Admin_451807\"")
        print(f"\n2. Run the application:")
        print(f"   python {filename}")
        return True
    else:
        print("❌ Bug found but couldn't fix automatically")
        return False


def show_usage():
    """Show usage instructions"""
    print("""
PyBank Bug Fix Script
═════════════════════

This script fixes the line 102 bug where:
    os.environ.get('Admin_451807')  ❌
should be:
    os.environ.get('DB_PASS')       ✅

Usage:
    python fix_bug.py app_secure.py

Or:
    python fix_bug.py [your_filename.py]
""")


def main():
    if len(sys.argv) < 2:
        show_usage()
        
        # Try to find app_secure.py automatically
        if os.path.exists('app_secure.py'):
            print("Found app_secure.py in current directory.")
            response = input("Fix it now? (y/n): ")
            if response.lower() == 'y':
                fix_line_102('app_secure.py')
        return
    
    filename = sys.argv[1]
    fix_line_102(filename)


if __name__ == "__main__":
    main()
