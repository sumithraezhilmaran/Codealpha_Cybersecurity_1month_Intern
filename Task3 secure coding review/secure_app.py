import sqlite3
import hashlib
import getpass
import pyotp
from datetime import datetime

DB_NAME = "auth_system.db"


#  DATABASE SETUP 
def init_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            otp_secret TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


#  SECURITY UTILS 
def create_hash(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()


#  USER MANAGEMENT 
def register_user():
    username = input("New username: ").strip()
    password = getpass.getpass("New password: ")

    salt = hashlib.sha256(username.encode()).hexdigest()[:16]
    password_hash = create_hash(password, salt)
    otp_secret = pyotp.random_base32()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, otp_secret)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, salt, otp_secret))

        conn.commit()
        print("\n✅ User registered successfully")
        print("🔐 OTP setup key (add to Google Authenticator):")
        print(otp_secret)

    except sqlite3.IntegrityError:
        print("❌ Username already exists")

    finally:
        conn.close()


# AUTHENTICATION 
def authenticate_user():
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT password_hash, salt, otp_secret
        FROM users WHERE username = ?
    """, (username,))

    record = cursor.fetchone()
    conn.close()

    if not record:
        print("❌ Invalid credentials")
        return

    stored_hash, salt, otp_secret = record
    input_hash = create_hash(password, salt)

    if input_hash != stored_hash:
        print("❌ Invalid credentials")
        return

    # OTP VERIFICATION 
    totp = pyotp.TOTP(otp_secret)
    otp_input = input("Enter OTP code: ").strip()

    if not totp.verify(otp_input):
        print("❌ Invalid OTP")
        return

    print("✅ Login successful (2FA verified)")


#  MAIN MENU 
def main():
    init_database()

    while True:
        print("\n--- Secure Auth System ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            register_user()
        elif choice == "2":
            authenticate_user()
        elif choice == "3":
            print("Goodbye 👋")
            break
        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
