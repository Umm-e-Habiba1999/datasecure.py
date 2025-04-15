import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode

# ------------------ Setup & Initialization ------------------

# Load or create Fernet key
FERNET_KEY_FILE = "fernet.key"
if not os.path.exists(FERNET_KEY_FILE):
    with open(FERNET_KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(FERNET_KEY_FILE, "rb") as f:
    cipher = Fernet(f.read())

# Load or initialize stored data
DATA_FILE = "data.json"
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Init session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_authorized" not in st.session_state:
    st.session_state.is_authorized = True

# ------------------ Helper Functions ------------------

def hash_passkey_pbkdf2(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return urlsafe_b64encode(key).decode(), salt.hex()

def verify_passkey(passkey, hashed, salt):
    derived_key, _ = hash_passkey_pbkdf2(passkey, bytes.fromhex(salt))
    return derived_key == hashed

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    for label, entry in stored_data.items():
        if entry["encrypted_text"] == encrypted_text:
            if verify_passkey(passkey, entry["passkey"], entry["salt"]):
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
            break
    st.session_state.failed_attempts += 1
    return None

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=4)

# ------------------ Streamlit UI ------------------

st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Securely **store** and **retrieve** encrypted data.")
    st.markdown("- ✅ **PBKDF2-hashed passkeys**")
    st.markdown("- ✅ **Encrypted with Fernet**")
    st.markdown("- ✅ **Stored in JSON**")
    st.markdown("- 🚫 **3 wrong attempts = lockout**")

# Store Data Page
elif choice == "Store Data":
    st.subheader("📦 Store New Encrypted Data")

    label = st.text_input("Label (e.g. username/title):")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey, salt = hash_passkey_pbkdf2(passkey)
            stored_data[label] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
                "salt": salt
            }
            save_data()
            st.success("✅ Data stored securely.")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Please fill in all fields.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Stored Data")

    if not st.session_state.is_authorized:
        st.warning("🔒 Too many failed attempts. Please reauthorize.")
        st.stop()

    encrypted_text = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Text:")
                st.code(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_authorized = False
                    st.warning("🚫 Too many failed attempts. Redirecting...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please provide both encrypted text and passkey.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorize Access")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Change for real usage
            st.session_state.failed_attempts = 0
            st.session_state.is_authorized = True
            st.success("✅ Reauthorized successfully.")
        else:
            st.error("❌ Incorrect password.")
