# fileshare_peer.py
import time
import os
import socket
import threading
import json
import crypto_utils
import secrets

# Constants
HOST = '0.0.0.0'
PORT = 5000
BROADCAST_PORT = PORT + 1  # UDP discovery port
SHARED_DIR = "shared_files"
USERS_FILE = "users.json"
SESSIONS_FILE = "sessions.json"
CHUNK_SIZE = 1024 * 1024  # 1MB

# Global state
sessions = {}
shared_files = {}  # filename -> {path, hash, owner, shared_with}

# Ensure shared directory exists
os.makedirs(SHARED_DIR, exist_ok=True)

# JSON persistence helpers


def load_json(path: str) -> dict:
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {}


def save_json(path: str, data: dict) -> None:
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)


# Initialize users and sessions
users = load_json(USERS_FILE)
sessions = load_json(SESSIONS_FILE)

# UDP discovery listener


def udp_discovery_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, BROADCAST_PORT))
    while True:
        data, addr = sock.recvfrom(1024)
        if data.decode().strip() == 'DISCOVER':
            reply = json.dumps({'host': socket.gethostbyname(
                socket.gethostname()), 'port': PORT})
            sock.sendto(reply.encode(), addr)

# Client handler


def handle_client_connection(conn: socket.socket, addr) -> None:
    conn_file = conn.makefile('rwb')
    try:
        line = conn_file.readline().decode().strip()
        if not line:
            return
        if line == 'REGISTER':
            conn_file.write(b'READY\n')
            conn_file.flush()
            uname = conn_file.readline().decode().strip()
            pwd = conn_file.readline().decode().strip()
            if uname in users:
                conn_file.write(b'ERROR: Username exists\n')
            else:
                h, s = crypto_utils.hash_password(pwd)
                users[uname] = {'hashed_password': h.hex(), 'salt': s.hex()}
                save_json(USERS_FILE, users)
                conn_file.write(b'REGISTER_SUCCESS\n')
            conn_file.flush()
            return
        if line == 'LOGIN':
            conn_file.write(b'LOGIN_READY\n')
            conn_file.flush()
            uname = conn_file.readline().decode().strip()
            pwd = conn_file.readline().decode().strip()
            if uname not in users:
                conn_file.write(b'ERROR: User not found\n')
            else:
                stored = users[uname]
                if crypto_utils.verify_password(pwd, bytes.fromhex(stored['hashed_password']), bytes.fromhex(stored['salt'])):
                    token = secrets.token_hex(16)
                    sessions[token] = uname
                    save_json(SESSIONS_FILE, sessions)
                    conn_file.write(f'LOGIN_SUCCESS {token}\n'.encode())
                else:
                    conn_file.write(b'ERROR: Invalid password\n')
            conn_file.flush()
            return
        token = line
        if token not in sessions:
            conn_file.write(b'ERROR: Invalid session\n')
            conn_file.flush()
            return
        user = sessions[token]
        cmd = conn_file.readline().decode().strip().upper()
        if cmd == 'LIST':
            files = [f for f, m in shared_files.items() if m['owner']
                     == user or user in m.get('shared_with', [])]
            resp = '\n'.join(files) if files else 'No files available.'
            conn_file.write(f'{resp}\n'.encode())
            conn_file.flush()
        elif cmd == 'SHARE':
            fname = conn_file.readline().decode().strip()
            user_list = conn_file.readline().decode().strip()
            meta = shared_files.get(fname)
            if not meta:
                conn_file.write(b'ERROR: File not found\n')
            elif meta['owner'] != user:
                conn_file.write(b'ERROR: Not owner\n')
            else:
                targets = [u.strip()
                           for u in user_list.split(',') if u.strip()]
                meta.setdefault('shared_with', []).extend(targets)
                conn_file.write(b'SHARE_SUCCESS\n')
            conn_file.flush()
        elif cmd == 'UPLOAD':
            conn_file.write(b'READY\n')
            conn_file.flush()
            fname = conn_file.readline().decode().strip()
            size_str = conn_file.readline().decode().strip()
            hsh = conn_file.readline().decode().strip()
            try:
                size = int(size_str)
            except ValueError:
                conn_file.write(b'ERROR: Invalid size\n')
                conn_file.flush()
                return
            path = os.path.join(SHARED_DIR, fname)
            rcvd = 0
            with open(path, 'wb') as f:
                while rcvd < size:
                    chunk = conn_file.read(min(CHUNK_SIZE, size-rcvd))
                    if not chunk:
                        break
                    f.write(chunk)
                    rcvd += len(chunk)
            if rcvd != size:
                conn_file.write(
                    f'ERROR: Incomplete ({rcvd}/{size})\n'.encode())
                conn_file.flush()
                return
            shared_files[fname] = {
                'path': path, 'hash': hsh, 'owner': user, 'shared_with': []}
            conn_file.write(f'UPLOAD_SUCCESS {rcvd} bytes\n'.encode())
            conn_file.flush()
        elif cmd == 'DOWNLOAD':
            conn_file.write(b'READY\n')
            conn_file.flush()
            fname = conn_file.readline().decode().strip()
            meta = shared_files.get(fname)
            if not meta or (meta['owner'] != user and user not in meta.get('shared_with', [])):
                conn_file.write(b'ERROR: Access denied\n')
                conn_file.flush()
                return
            ph = meta['hash']
            path = meta['path']
            sz = os.path.getsize(path)
            conn_file.write(f'{ph}\n{sz}\n'.encode())
            conn_file.flush()
            ack = conn_file.readline().decode().strip()
            if ack != 'READY':
                return
            with open(path, 'rb') as f:
                while True:
                    c = f.read(CHUNK_SIZE)
                    if not c:
                        break
                    conn.sendall(c)
        else:
            conn_file.write(b'ERROR: Unknown command\n')
            conn_file.flush()
    except Exception as e:
        print(f'Error [{addr}]: {e}')
    finally:
        conn_file.close()
        conn.close()


def start():
    threading.Thread(target=udp_discovery_listener, daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"Peer on {HOST}:{PORT} (discovery {BROADCAST_PORT})")
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle_client_connection,
                         args=(client, addr), daemon=True).start()


if __name__ == '__main__':
    start()

# fileshare_client.py

# ========== Configuration Constants ==========
PEER_HOST = '127.0.0.1'
PEER_PORT = 5000
BROADCAST_PORT = PEER_PORT + 1
CHUNK_SIZE = 1024 * 1024  # 1MB

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
        resp = s.recv(1024).decode().strip()
        print(resp)


def upload_file() -> None:
    if not session_token:
        print('You must log in before uploading files.')
        return
    filepath = input("Enter file path to upload: ").strip()
    if not os.path.isfile(filepath):
        print('File not found.')
        return
    plaintext_hash = crypto_utils.hash_file(filepath)
    with open(filepath, 'rb') as f:
        data = f.read()
    if not data:
        print("Cannot upload empty file.")
        return
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
        enc_size = int(s.recv(1024).decode().strip())
        s.sendall(b'READY\n')
        data = bytearray()
        while len(data) < enc_size:
            chunk = s.recv(CHUNK_SIZE)
            if not chunk:
                break
            data.extend(chunk)
        iv = data[:16]
        ciphertext = data[16:]
        plaintext = crypto_utils.decrypt_bytes(iv, ciphertext, SYMM_KEY)
        if crypto_utils.hash_bytes(plaintext) != plaintext_hash:
            print('Integrity check failed!')
            return
        with open(dest, 'wb') as f:
            f.write(plaintext)
        print(f"Downloaded {filename} as {dest}")


def login_user() -> None:
    # Existing login logic...
    pass


def register_user() -> None:
    # Existing register logic...
    pass


if __name__ == '__main__':
    peers = discover_peers()
    if peers:
        PEER_HOST, PEER_PORT = peers[0]
        print(f"Discovered peer at {PEER_HOST}:{PEER_PORT}")
    else:
        print("No peers found; using defaults.")

    while True:
        print("\nCipherShare Client")
        print("1. List shared files")
        print("2. Upload a file")
        print("3. Download a file")
        print("4. Share a file with users")
        print("5. Login user")
        print("6. Register new user")
        print("7. Exit")
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
            break
        else:
            print("Invalid option. Please choose 1-7.")
