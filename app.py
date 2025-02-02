from flask import Flask, render_template, request
from Crypto.Cipher import AES
import base64
import binascii  # Import for handling Base64 errors

app = Flask(__name__)

# Padding function for AES (since AES requires a block size of 16)
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

# AES Encryption
def encrypt(plain_text, key):
    key = key.ljust(16)[:16].encode()  # Ensure key is 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(plain_text).encode())
    return base64.b64encode(encrypted_text).decode()

# AES Decryption (Fix applied)
def decrypt(encrypted_text, key):
    try:
        key = key.ljust(16)[:16].encode()
        encrypted_bytes = base64.b64decode(encrypted_text)  # Decode Base64 properly
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_text = unpad(cipher.decrypt(encrypted_bytes).decode())
        return decrypted_text
    except (binascii.Error, ValueError):
        return "Invalid ciphertext! Ensure you provide a valid Base64-encoded encrypted text."

@app.route("/", methods=["GET", "POST"])
def index():
    encrypted_text = ""
    decrypted_text = ""
    message = ""
    key = ""

    if request.method == "POST":
        message = request.form["message"]
        key = request.form["key"]

        if "encrypt" in request.form:
            encrypted_text = encrypt(message, key)
        elif "decrypt" in request.form:
            decrypted_text = decrypt(message, key)

    return render_template("index.html", encrypted_text=encrypted_text, decrypted_text=decrypted_text, message=message, key=key)

if __name__ == "__main__":
    app.run(debug=True)
