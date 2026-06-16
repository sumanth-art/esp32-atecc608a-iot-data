from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES

# MUST match the Km stored in your ATECC Slot 8
Km = bytes.fromhex("REPLACE_WITH_YOUR_SLOT8_KM_HEX")

def decrypt_data(Km, nonce_hex, cipher_hex, tag_hex):
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(cipher_hex)
    tag = bytes.fromhex(tag_hex)

    # 1. Derive SAME Session Key (Ks)
    h = HMAC.new(Km, digestmod=SHA256)
    h.update(nonce)
    Ks = h.digest()[:16]

    # 2. Decrypt AES-GCM
    cipher = AES.new(Ks, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"Decrypted Data: {plaintext.decode()}")
    except Exception as e:
        print("Decryption Failed: Data tampered or wrong key!")

# Paste the values from your ESP32 Serial Monitor here
decrypt_data(Km, "PASTE_NONCE_HERE", "PASTE_CIPHER_HERE", "PASTE_TAG_HERE")





