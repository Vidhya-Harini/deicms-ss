import sqlite3
c = sqlite3.connect('deicms.db')
r = c.execute('PRAGMA integrity_check').fetchall()
print('Integrity:', r)
tbls = c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print('Tables:', tbls)
for t in tbls:
    cnt = c.execute(f"SELECT COUNT(*) FROM {t[0]}").fetchone()[0]
    print(f"  {t[0]}: {cnt} rows")
c.close()
