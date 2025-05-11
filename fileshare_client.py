import os
import time
import json
import socket
import crypto_utils

# ========== Configuration Constants ==========
PEER_HOST = '127.0.0.1'
PEER_PORT = 5000
BROADCAST_PORT = PEER_PORT + 1
CHUNK_SIZE = 1024 * 1024  # 1MB
CREDENTIALS_FILE = "credentials.json"

# ========== Global State ==========
session_token = None
SYMM_KEY = crypto_utils.get_symmetric_key()

# ========== Networking Helpers ==========
def send_command(sock: socket.socket, command: str) -> None:
    if session_token:
        sock.sendall(f"{session_token}\n".encode())
    sock.sendall(f"{command}\n".encode())

# ========== Peer Discovery ==========
def discover_peers(timeout: float = 2.0) -> list[tuple[str, int]]:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp.settimeout(timeout)
    udp.sendto(b'DISCOVER', ('<broadcast>', BROADCAST_PORT))
    found = set()
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, addr = udp.recvfrom(1024)
            info = json.loads(data.decode())
            found.add((info['host'], info['port']))
        except socket.timeout:
            break
    udp.close()
    return list(found)

# ========== Core Functions ==========
def list_files() -> None:
    if not session_token:
        print('Please log in to view shared files.')
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'LIST')
        data = s.recv(8192).decode()
        print('Shared files on server:')
        print(data)

def share_file() -> None:
    if not session_token:
        print('Please log in to share files.')
        return
    filename = input("Enter file name to share: ").strip()
    users = input("Enter comma-separated usernames: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'SHARE')
        s.sendall(f"{filename}\n".encode())
        s.sendall(f"{users}\n".encode())
        if resp.startswith("SHARE_WARNING"):
            print("Warning:", resp.split(":", 1)[1].strip())


def upload_file() -> None:
    if not session_token:
        print('You must log in before uploading files.')
        return
    filepath = input("Enter file path to upload: ").strip()
    if not os.path.isfile(filepath):
        print('File not found.')
        return  
    
    plaintext_hash = crypto_utils.hash_file(filepath)
    if os.path.getsize(filepath) == 0:
        print("Cannot upload an empty file.")
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    
    iv, ciphertext = crypto_utils.encrypt_bytes(data, SYMM_KEY)
    payload = iv + ciphertext
    enc_size = len(payload)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'UPLOAD')
        resp = s.recv(1024).decode().strip()
        if resp != 'READY':
            print('Upload init failed.')
            return
        s.sendall(f"{os.path.basename(filepath)}\n".encode())
        s.sendall(f"{enc_size}\n".encode())
        s.sendall(f"{plaintext_hash}\n".encode())
        s.sendall(payload)
        print(s.recv(1024).decode().strip())

def download_file() -> None:
    if not session_token:
        print('You must log in before downloading files.')
        return
    filename = input("Enter file name to download: ").strip()
    dest = input("Save as: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'DOWNLOAD')
        resp = s.recv(1024).decode().strip()
        if resp != 'READY':
            print('Download init failed.')
            return
        s.sendall(f"{filename}\n".encode())
        plaintext_hash = s.recv(1024).decode().strip()
        if plaintext_hash.startswith("ERROR"):
            print(plaintext_hash)
            return
        size_response = s.recv(1024).decode().strip()
        if size_response.startswith("ERROR"):
            print(size_response)
            return
        try:
            enc_size = int(size_response)
        except ValueError:
            print(f"Invalid size received: {size_response}")
            return
        s.sendall(b'READY\n')
        data = bytearray()
        while len(data) < enc_size:
            chunk = s.recv(CHUNK_SIZE)
            if not chunk:
                break
            data.extend(chunk)
        iv = data[:16]
        ciphertext = data[16:]
        try:
            plaintext = crypto_utils.decrypt_bytes(iv, ciphertext, SYMM_KEY)
        except ValueError:
            print("Decryption failed — file may have been tampered with.")
            return

        if crypto_utils.hash_bytes(plaintext) != plaintext_hash:
            print('Integrity check failed!')
            return
        with open(dest, 'wb') as f:
            f.write(plaintext)
        print(f"Downloaded {filename} as {dest}")

# ========== Authentication ==========
def register_user() -> None:
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((PEER_HOST, PEER_PORT))
            s.sendall(b'REGISTER\n')
            resp = s.recv(1024).decode().strip()
            if resp != 'READY':
                print('Unable to register at this time. Please try again later.')
                return
            s.sendall(f"{username}\n".encode())
            s.sendall(f"{password}\n".encode())
            result = s.recv(1024).decode().strip()
            if result.startswith('ERROR'):
                print('Registration failed:', result.split(':', 1)[1].strip())
            else:
                print('Registration successful! You can now log in.')
        except Exception:
            print('Could not connect to server. Please check your network and try again.')

def login_user() -> None:
    global session_token
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((PEER_HOST, PEER_PORT))
            s.sendall(b'LOGIN\n')
            resp = s.recv(1024).decode().strip()
            if resp != 'LOGIN_READY':
                print('Unable to log in at this time. Please try again later.')
                return
            s.sendall(f"{username}\n".encode())
            s.sendall(f"{password}\n".encode())
            parts = s.recv(1024).decode().strip().split()
            if parts[0] == 'LOGIN_SUCCESS':
                session_token = parts[1]
                salt_hex = parts[2] if len(parts) > 2 else None
                print('Login successful!')
                if salt_hex:
                    salt = bytes.fromhex(salt_hex)
                    crypto_utils.save_encrypted_credentials(session_token, password, salt)
                else:
                    print("Warning: salt not received — cannot save session securely.")
            else:
                error_msg = ' '.join(parts[1:]) if len(parts) > 1 else 'Invalid credentials.'
                print('Login failed:', error_msg)
        except Exception:
            print('Could not connect to server. Please check your network and try again.')

def logout_user() -> None:
    global session_token
    session_token = None  # Clear session in memory
    try:
        os.remove(CREDENTIALS_FILE)
        print("Logged out successfully.")
    except FileNotFoundError:
        print("No saved session found.")


# ========== Menu ==========
if __name__ == '__main__':
    peers = discover_peers()
    if peers:
        PEER_HOST, PEER_PORT = peers[0]
        print(f"Discovered peer at {PEER_HOST}:{PEER_PORT}")
    else:
        print("No peers found; using defaults.")

    
    if os.path.exists(CREDENTIALS_FILE):
        print("Encrypted credentials found.")
        password = input("Enter password to auto-login: ")
        session_token = crypto_utils.load_encrypted_credentials(password)
        if session_token:
            print("Auto-login successful!")
        else:
            print("Auto-login failed.")

    while True:
        print("\nCipherShare Client")
        print("1. List shared files")
        print("2. Upload a file")
        print("3. Download a file")
        print("4. Share a file with users")
        print("5. Login user")
        print("6. Register new user")
        print("7. Logout")
        print("8. Exit")
        choice = input("Choice: ").strip()
        if choice == '1':
            list_files()
        elif choice == '2':
            upload_file()
        elif choice == '3':
            download_file()
        elif choice == '4':
            share_file()
        elif choice == '5':
            login_user()
        elif choice == '6':
            register_user()
        elif choice == '7':
            logout_user()
        elif choice == '8':
            break
        else:
            print("Invalid option. Please choose 1–8.")
