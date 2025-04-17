import streamlit as st
import hashlib
import base64
import json
import os
from cryptography.fernet import Fernet

# --- Config files ---
KEY_FILE = "secret.key"
DATA_FILE = "vault_data.json"

# --- Load or create encryption key ---
def get_cipher():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return Fernet(key)

cipher = get_cipher()

# --- Load or create user data ---
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        users = json.load(f)
else:
    users = {}

# --- Save user data ---
def save_users():
    with open(DATA_FILE, "w") as f:
        json.dump(users, f)

# --- Secure password hashing ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Encryption/Decryption ---
def encrypt_message(msg):
    return cipher.encrypt(msg.encode()).decode()

def decrypt_message(token):
    return cipher.decrypt(token.encode()).decode()

# --- Streamlit UI ---
st.set_page_config(page_title="Secure Vault", page_icon="🔐")
st.title("🔐 Secure Vault")

menu = ["Login", "Encrypt", "Decrypt"]
choice = st.sidebar.radio("Go to", menu)

# --- Session Defaults ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None

# --- Login ---
if choice == "Login":
    st.subheader("👤 Login or Register")
    username = st.text_input("Username")
    password = st.text_input("Passkey", type="password")
    if st.button("Login / Register"):
        hashed = hash_passkey(password)
        if username in users:
            if users[username]["passkey"] == hashed:
                st.success("✅ Logged in")
                st.session_state.logged_in = True
                st.session_state.user = username
            else:
                st.error("❌ Wrong password")
        else:
            users[username] = {"passkey": hashed, "data": []}
            save_users()
            st.success("✅ New user created and logged in")
            st.session_state.logged_in = True
            st.session_state.user = username

# --- Encrypt Data ---
elif choice == "Encrypt":
    st.subheader("🔐 Encrypt a Message")
    if st.session_state.logged_in:
        message = st.text_area("Enter message to encrypt")
        if st.button("Encrypt"):
            encrypted = encrypt_message(message)
            users[st.session_state.user]["data"].append(encrypted)
            save_users()
            st.success("Message encrypted and saved!")
            st.code(encrypted)
    else:
        st.warning("Please log in first")

# --- Decrypt Data ---
elif choice == "Decrypt":
    st.subheader("🔓 Decrypt Encrypted Text")
    if st.session_state.logged_in:
        encrypted_text = st.text_area("Paste encrypted text here")
        if st.button("Decrypt"):
            try:
                decrypted = decrypt_message(encrypted_text.strip())
                st.success(f"Decrypted Message: {decrypted}")
            except Exception:
                st.error("❌ Could not decrypt. Make sure the text is correct and from this app.")
    else:
        st.warning("Please log in first")
