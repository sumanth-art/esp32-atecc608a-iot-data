import socket
import hmac
import hashlib
from Crypto.Cipher import AES


# --- CONFIGURATION ---
MASTER_KEY = bytes.fromhex("5EAC8219DFBB410723881ABC9044FD1277A13309EEBC48912F30CB8A51D40267")
LISTEN_IP = "0.0.0.0"  # Listen on all available interfaces
LISTEN_PORT = 8080

#  To remember seen IVs
seen_ivs = set()

def derive_session_key(iv_bytes):
    """ Matches atcab_sha_hmac(iv, 32, 5, ...) """
    # Hardware performs standard HMAC-SHA256
    full_hmac = hmac.new(MASTER_KEY, iv_bytes, hashlib.sha256).digest()
    # We used AES-128 on ESP32, so we take the first 16 bytes
    return full_hmac[:16]


def start_listener():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
   
    print(f"Listening for secure IoT data on port {LISTEN_PORT}...\n")


    while True:
        data, addr = sock.recvfrom(1024)
       
        if len(data) < 48:
            print(">>> Received malformed packet.")
            continue


        # 1. Extract parts
        received_iv = data[:32]
        received_tag = data[32:48]
        ciphertext = data[48:]

        # 2. To Stop Replay Attacks
        if received_iv in seen_ivs:
            print(f">>> SECURITY ALERT: Replay Attack Detected! Duplicate IV rejected.")
            continue
        seen_ivs.add(received_iv)


        # 3. Derive Session Key
        session_key = derive_session_key(received_iv)


        print("="*60)
        print(f"SOURCE ADDRESS      : {addr[0]}:{addr[1]}")
       
        # DISPLAY: Encrypted Data (Ciphertext + Tag)
        print(f"ENCRYPTED PAYLOAD   : {ciphertext.hex().upper()}")
        print(f"RECEIVED MAC (TAG)  : {received_tag.hex().upper()}")


        # 4. Decrypt and Verify
        try:
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=received_iv[:12])
           
            # If this line succeeds, both key and MAC are valid
            decrypted_data = cipher.decrypt_and_verify(ciphertext, received_tag)
           
            print(f"SESSION KEY STATUS  : CORRECT (Generated Using Master Secret)")
            print(f"MAC VERIFICATION    : SUCCESS (Integrity Verified)")
            print(f"DECRYPTED DATA      : {decrypted_data.decode('utf-8')}")


        except ValueError:
            # This specific error triggers if decrypt_and_verify fails the MAC check
            print(f"SESSION KEY STATUS  : UNKNOWN (Potentially correct)")
            print(f"MAC VERIFICATION    : FAILED! (Data tampered or wrong Master Key)")
            print(f"DECRYPTED DATA      : [REDACTED/UNAVAILABLE]")
       
        except Exception as e:
            print(f"SYSTEM ERROR        : {e}")
           
        print("="*60 + "\n")




if __name__ == "__main__":
    start_listener()
