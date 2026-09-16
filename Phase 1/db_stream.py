import os
import time
import sqlite3
import json
from supabase import create_client


# ============================================================
# CONFIGURATION
# ============================================================

DB_PATH = #path to the local DB
LOCAL_TABLE = #Name of the table

LAST_ID_FILE = #path so the log file

SUPABASE_URL = #Url

# Put your publishable key here
SUPABASE_KEY = #key

supabase = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)


# ============================================================
# LAST PROCESSED ID
# ============================================================

def get_last_id():

    if os.path.exists(LAST_ID_FILE):

        try:

            with open(LAST_ID_FILE, "r") as f:
                return int(f.read().strip())

        except:
            return 0

    return 0


def save_last_id(value):

    with open(LAST_ID_FILE, "w") as f:
        f.write(str(value))


# ============================================================
# SQLITE → JSON
# ============================================================

def row_to_json(row):

    # SQLite Row → Python dictionary
    data = dict(row)

    # Dictionary → JSON string
    json_data = json.dumps(
        data,
        default=str
    )

    # JSON string → Python dictionary
    # Supabase client sends this as JSON
    payload = json.loads(json_data)

    return payload


# ============================================================
# SEND ONE ROW TO SUPABASE
# ============================================================

def send_to_supabase(payload):

    response = (
        supabase
        .table("analysis_results")
        .insert(payload)
        .execute()
    )

    return response


# ============================================================
# PROCESS NEW SQLITE ROWS
# ============================================================

def process_database():

    global last_id

    if not os.path.exists(DB_PATH):

        print(f"[!] Database not found: {DB_PATH}")
        return

    conn = None

    try:

        conn = sqlite3.connect(DB_PATH)

        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        # Get rows that haven't been synchronized
        cursor.execute(
            f"""
            SELECT *
            FROM {LOCAL_TABLE}
            WHERE id > ?
            ORDER BY id ASC
            """,
            (last_id,)
        )

        rows = cursor.fetchall()

        if not rows:
            return

        print(f"[*] Found {len(rows)} new row(s).")

        # ----------------------------------------------------
        # Process each row
        # ----------------------------------------------------

        for row in rows:

            sqlite_id = row["id"]

            print()
            print("=" * 60)
            print(f"[*] Processing SQLite ID: {sqlite_id}")

            # ------------------------------------------------
            # Convert row → JSON
            # ------------------------------------------------

            payload = row_to_json(row)

            print("[*] JSON:")

            print(
                json.dumps(
                    payload,
                    indent=4,
                    default=str
                )
            )

            # ------------------------------------------------
            # Send JSON to Supabase
            # ------------------------------------------------

            try:

                send_to_supabase(payload)

                print(
                    f"[+] SQLite ID {sqlite_id} "
                    "sent to Supabase."
                )

                # Only save ID after successful insert
                last_id = sqlite_id

                save_last_id(last_id)

            except Exception as e:

                print(
                    f"[!] Failed to send "
                    f"SQLite ID {sqlite_id}"
                )

                print(f"[!] Error: {e}")

                # Stop here.
                # This row will be retried next cycle.
                break

    except sqlite3.Error as e:

        print(f"[!] SQLite error: {e}")

    except Exception as e:

        print(f"[!] Unexpected error: {e}")

    finally:

        if conn:
            conn.close()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print(" SecureMailScope SQLite → Supabase JSON Bridge")
    print("=" * 60)

    print()
    print(f"[*] SQLite DB : {DB_PATH}")
    print(f"[*] SQLite table : {LOCAL_TABLE}")
    print(f"[*] Supabase table : analysis_results")
    print(f"[*] Supabase URL : {SUPABASE_URL}")

    last_id = get_last_id()

    print(
        f"[*] Last synchronized ID: {last_id}"
    )

    print()
    print("[+] Starting database monitoring...")
    print("[+] Poll interval: 2 seconds")
    print()

    while True:

        try:

            process_database()

        except KeyboardInterrupt:

            print()
            print("[*] Stopped by user.")
            break

        except Exception as e:

            print(f"[!] Error: {e}")

        time.sleep(2)
