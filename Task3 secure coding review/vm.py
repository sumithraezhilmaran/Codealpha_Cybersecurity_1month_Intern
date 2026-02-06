import hashlib
from datetime import datetime

# ================= CONFIG =================
USER_DATA = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest()
}

MAX_TRIES = 3
attempts = 0
LOG_FILE = "secure_login_logs.txt"
# =========================================


def encrypt_password(raw_password: str) -> str:
    """Returns hashed password"""
    return hashlib.sha256(raw_password.encode()).hexdigest()


def save_log(user: str, status: str):
    """Logs login result without sensitive info"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        log.write(f"{timestamp} | User={user} | Status={status}\n")


def login():
    global attempts

    if attempts >= MAX_TRIES:
        print("🔒 Account locked. Too many failed attempts.")
        return

    username = input("Enter username: ").strip()
    password = input("Enter password: ")

    encrypted_input = encrypt_password(password)
    stored_hash = USER_DATA.get(username)

    if stored_hash and encrypted_input == stored_hash:
        print("✅ Login successful")
        save_log(username, "SUCCESS")
        attempts = 0
    else:
        attempts += 1
        print("❌ Login failed")
        save_log(username, "FAILED")
        print(f"Attempts remaining: {MAX_TRIES - attempts}")


if __name__ == "__main__":
    login()

