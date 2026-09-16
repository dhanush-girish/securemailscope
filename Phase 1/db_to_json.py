import sqlite3
import json

DB_PATH = #path of db

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

cursor = conn.cursor()

cursor.execute("""
    SELECT *
    FROM sessions
    LIMIT 1
""")

row = cursor.fetchone()

if row:
    data = dict(row)

    print(json.dumps(data, indent=4))
else:
    print("No records found.")

conn.close()
