"""
Database recovery script.
Attempts to recover data from a malformed SQLite database using multiple strategies.
"""
import sqlite3
import os
import shutil

def try_recover():
    db_path = "deicms.db"
    backup_path = "deicms_corrupt_backup.db"
    recovered_path = "deicms_recovered.db"

    if not os.path.exists(db_path):
        print("Database not found!")
        return False

    # First backup
    if not os.path.exists(backup_path):
        shutil.copy2(db_path, backup_path)
        print(f"Backed up to {backup_path}")

    # Strategy 1: iterdump on corrupt DB (partial)
    print("\n=== Strategy 1: iterdump ===")
    recovered_sql = []
    try:
        old_conn = sqlite3.connect(db_path)
        old_conn.row_factory = sqlite3.Row
        for line in old_conn.iterdump():
            recovered_sql.append(line)
        old_conn.close()
        print(f"Dumped {len(recovered_sql)} SQL statements")

        # Write new db
        if os.path.exists(recovered_path):
            os.remove(recovered_path)
        new_conn = sqlite3.connect(recovered_path)
        new_conn.executescript("\n".join(recovered_sql))
        new_conn.commit()
        new_conn.close()
        print("Recovered database created!")

        # Verify
        v_conn = sqlite3.connect(recovered_path)
        result = v_conn.execute("PRAGMA integrity_check").fetchall()
        v_conn.close()
        print(f"Integrity check: {result}")
        if result and result[0][0] == "ok":
            # Replace original
            os.replace(recovered_path, db_path)
            print("SUCCESS: Original database replaced with recovered version!")
            return True
        else:
            print("Partial recovery - integrity issues remain")
            return False
    except sqlite3.DatabaseError as e:
        print(f"iterdump failed: {e}")

    # Strategy 2: Try sqlite3 CLI-style recovery
    print("\n=== Strategy 2: Manual schema+data recovery ===")
    try:
        old_conn = sqlite3.connect(db_path)
        # Get schema from sqlite_master
        schema_rows = []
        try:
            schema_rows = old_conn.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL"
            ).fetchall()
            print(f"Got schema: {[r[1] for r in schema_rows]}")
        except Exception as e2:
            print(f"Schema read failed: {e2}")

        if os.path.exists(recovered_path):
            os.remove(recovered_path)
        new_conn = sqlite3.connect(recovered_path)

        # Recreate schema
        for row in schema_rows:
            try:
                new_conn.execute(row[2])
                print(f"  Created: {row[1]}")
            except Exception as e3:
                print(f"  Skip {row[1]}: {e3}")
        new_conn.commit()

        # Try to copy data table by table
        tables = [r[1] for r in schema_rows if r[0] == "table" and not r[1].startswith("sqlite_")]
        for table in tables:
            try:
                rows = old_conn.execute(f"SELECT * FROM {table}").fetchall()
                if rows:
                    cols = len(rows[0])
                    placeholders = ",".join(["?"] * cols)
                    new_conn.executemany(f"INSERT OR IGNORE INTO {table} VALUES ({placeholders})", rows)
                    new_conn.commit()
                    print(f"  Copied {len(rows)} rows from {table}")
                else:
                    print(f"  {table}: empty")
            except Exception as e4:
                print(f"  {table}: data copy failed - {e4}")

        old_conn.close()
        new_conn.close()

        # Verify recovered
        v_conn = sqlite3.connect(recovered_path)
        result = v_conn.execute("PRAGMA integrity_check").fetchall()
        v_conn.close()
        print(f"Integrity check: {result}")
        if result and result[0][0] == "ok":
            os.replace(recovered_path, db_path)
            print("SUCCESS: Partial recovery successful!")
            return True
        else:
            print("Partial recovery stored at deicms_recovered.db")

    except Exception as e:
        print(f"Strategy 2 failed: {e}")

    return False


def create_fresh_db():
    """If recovery fails, delete the corrupt DB and let Flask recreate it with seed data."""
    print("\n=== Creating fresh database ===")
    db_path = "deicms.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    print("Corrupt database deleted. Flask will recreate schema on next startup.")
    print("Run: python seed.py  to populate with sample data.")


if __name__ == "__main__":
    success = try_recover()
    if not success:
        print("\nRecovery unsuccessful. Choose an option:")
        print("1. Keep the corrupt backup and create a fresh database (recommended)")
        print("2. Exit")
        choice = input("Enter choice (1/2): ").strip()
        if choice == "1":
            create_fresh_db()
        else:
            print("No changes made.")
