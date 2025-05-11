# fileshare_peer.py
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

# User/session persistence


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
        # First line: REGISTER, LOGIN, or session token
        line = conn_file.readline().decode().strip()
        if not line:
            return

        # Registration
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

        # Login
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
                    
                    salt = users[uname]['salt']
                    conn_file.write(f'LOGIN_SUCCESS {token} {stored["salt"]}\n'.encode())

                else:
                    conn_file.write(b'ERROR: Invalid password\n')
            conn_file.flush()
            return

        # Session validation
        token = line
        if token not in sessions:
            conn_file.write(b'ERROR: Invalid session\n')
            conn_file.flush()
            return
        user = sessions[token]

        # Next: command
        cmd = conn_file.readline().decode().strip().upper()
        if cmd == 'LIST':
            # include own and shared-with files
            files = [f for f, m in shared_files.items() if m['owner']
                     == user or user in m.get('shared_with', [])]
            resp = '\n'.join(files) if files else 'No files available.'
            conn_file.write(f'{resp}\n'.encode())
            conn_file.flush()

        elif cmd == 'SHARE':
            # SHARE <filename> <user1,user2,...>
            fname = conn_file.readline().decode().strip()
            user_list = conn_file.readline().decode().strip()
            meta = shared_files.get(fname)
            if not meta:
                conn_file.write(b'ERROR: File not found\n')
            elif meta['owner'] != user:
                conn_file.write(b'ERROR: You can only share files you uploaded\n')
            else:
                targets = [u.strip() for u in user_list.split(',') if u.strip()]
                invalid_users = [u for u in targets if u not in users]

                # Still share with all targets regardless
                meta.setdefault('shared_with', []).extend(targets)

                if invalid_users:
                    msg = f"SHARE_WARNING: Users not found: {', '.join(invalid_users)}"
                    conn_file.write(f"{msg}\n".encode())
                else:
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

# Server startup


def start():
    # Start UDP discovery
    threading.Thread(target=udp_discovery_listener, daemon=True).start()
    # Start TCP server
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
