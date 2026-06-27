"""
deicms_db_audit.py
Full inspection of deicms.db — schema, row counts, and sample data for every table.
"""
import sqlite3, json, textwrap

DB_PATH = "deicms.db"
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# ── helpers ──────────────────────────────────────────────────────────────────
def hr(char="─", width=90): print(char * width)
def section(title): hr("═"); print(f"  {title}"); hr("═")
def sub(title): hr("─"); print(f"  {title}"); hr("─")

# ── 1. General info ──────────────────────────────────────────────────────────
section("deicms.db  ·  SQLite Database Audit")

pragma_info = {
    "SQLite version": conn.execute("SELECT sqlite_version()").fetchone()[0],
    "Page size (bytes)": conn.execute("PRAGMA page_size").fetchone()[0],
    "Page count": conn.execute("PRAGMA page_count").fetchone()[0],
    "Integrity check": conn.execute("PRAGMA integrity_check").fetchone()[0],
    "Foreign keys enabled": conn.execute("PRAGMA foreign_keys").fetchone()[0],
    "Journal mode": conn.execute("PRAGMA journal_mode").fetchone()[0],
}
for k, v in pragma_info.items():
    print(f"  {k:<28} {v}")

# ── 2. All tables with row counts ────────────────────────────────────────────
section("TABLES OVERVIEW")
tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]

totals = {}
for t in tables:
    cnt = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    totals[t] = cnt
    status = "✅ has data" if cnt > 0 else "❌ EMPTY"
    print(f"  {t:<30}  {cnt:>5} rows   {status}")

# ── 3. Detailed table inspection ─────────────────────────────────────────────
def show_table(name, max_rows=5):
    sub(f"TABLE: {name}  ({totals[name]} rows)")

    # Schema
    cols_raw = conn.execute(f"PRAGMA table_info({name})").fetchall()
    print("  COLUMNS:")
    for c in cols_raw:
        pk   = " [PK]" if c["pk"] else ""
        nn   = " NOT NULL" if c["notnull"] else ""
        defv = f" DEFAULT {c['dflt_value']}" if c["dflt_value"] else ""
        print(f"    {c['cid']:>2}. {c['name']:<30} {c['type']:<20}{pk}{nn}{defv}")

    # Foreign keys
    fks = conn.execute(f"PRAGMA foreign_key_list({name})").fetchall()
    if fks:
        print("  FOREIGN KEYS:")
        for fk in fks:
            print(f"    {fk['from']:<25} → {fk['table']}.{fk['to']}")

    # Indexes
    idxs = conn.execute(f"PRAGMA index_list({name})").fetchall()
    if idxs:
        print("  INDEXES:")
        for ix in idxs:
            print(f"    {ix['name']}  ({'UNIQUE' if ix['unique'] else 'non-unique'})")

    # Data sample
    if totals[name] == 0:
        print("  ⚠️  NO DATA IN THIS TABLE")
    else:
        rows = conn.execute(f"SELECT * FROM {name} LIMIT {max_rows}").fetchall()
        col_names = [c[1] for c in conn.execute(f"PRAGMA table_info({name})")]
        print(f"  SAMPLE DATA (first {min(max_rows, totals[name])} rows):")
        for row in rows:
            print("  ┌" + "─" * 86)
            for col in col_names:
                val = row[col]
                if isinstance(val, str) and len(val) > 60:
                    val = val[:57] + "..."
                print(f"  │  {col:<28} {str(val)}")
        print("  └" + "─" * 86)

for t in tables:
    show_table(t)

# ── 4. Relationship summary ───────────────────────────────────────────────────
section("RELATIONSHIP MAP  (FK graph)")
for t in tables:
    fks = conn.execute(f"PRAGMA foreign_key_list({t})").fetchall()
    for fk in fks:
        print(f"  {t}.{fk['from']:<35} ──►  {fk['table']}.{fk['to']}")

# ── 5. Quick data health check ───────────────────────────────────────────────
section("DATA HEALTH SUMMARY")
checks = [
    ("investigators",   "4 accounts (admin/lead/analyst/read-only)"),
    ("cases",           "8 case records"),
    ("evidence_items",  "12 evidence items"),
    ("custody_logs",    "Transfer + upload chain entries"),
    ("audit_records",   "Security event audit trail"),
    ("case_access",     "Case member access-control rows"),
]
for table, expected in checks:
    cnt = totals.get(table, 0)
    ok = cnt > 0
    print(f"  {'✅' if ok else '❌'}  {table:<22}  {cnt:>4} rows  ← expected: {expected}")

conn.close()
print()
hr("═")
print("  Audit complete.")
hr("═")
