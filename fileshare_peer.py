import os
import socket
import threading
import json
import secrets
import crypto_utils

HOST = '0.0.0.0'
PORT = 5000
SHARED_DIR = "shared_files"
USERS_FILE = "users.json"

# Session token -> username
sessions = {}
# filename -> filepath
shared_files = {}


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)


# Ensure shared directory exists
if not os.path.exists(SHARED_DIR):
    os.makedirs(SHARED_DIR)


def handle_client_connection(conn, addr):
    print(f"Accepted connection from {addr}")
    conn_file = conn.makefile('rwb')
    try:
        # First line: REGISTER, LOGIN, or session token
        line = conn_file.readline().decode().strip()
        if not line:
            return
        # Registration flow
        if line == 'REGISTER':
            conn_file.write(b'READY\n')
            conn_file.flush()
            username = conn_file.readline().decode().strip()
            password = conn_file.readline().decode().strip()
            users = load_users()
            if username in users:
                conn_file.write(b'ERROR: Username exists\n')
            else:
                hashed, salt = crypto_utils.hash_password(password)
                users[username] = {
                    'hashed_password': hashed.hex(), 'salt': salt.hex()}
                save_users(users)
                conn_file.write(b'REGISTER_SUCCESS\n')
            conn_file.flush()
            return
        # Login flow
        if line == 'LOGIN':
            conn_file.write(b'LOGIN_READY\n')
            conn_file.flush()
            username = conn_file.readline().decode().strip()
            password = conn_file.readline().decode().strip()
            users = load_users()
            if username not in users:
                conn_file.write(b'ERROR: User not found\n')
            else:
                stored = users[username]
                if crypto_utils.verify_password(
                    password,
                    bytes.fromhex(stored['hashed_password']),
                    bytes.fromhex(stored['salt'])
                ):
                    token = secrets.token_hex(16)
                    sessions[token] = username
                    conn_file.write(f'LOGIN_SUCCESS {token}\n'.encode())
                    print(f"User {username} logged in, session {token}")
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
        username = sessions[token]
        # Next line: actual command
        command = conn_file.readline().decode().strip().upper()
        print(f"User {username} ({token}) issued {command}")
        # LIST command
        if command == 'LIST':
            file_list = '\n'.join(shared_files.keys()) or 'No files available.'
            conn_file.write(f'{file_list}\n'.encode())
            conn_file.flush()
        # UPLOAD command
        elif command == 'UPLOAD':
            conn_file.write(b'READY\n')
            conn_file.flush()
            filename = conn_file.readline().decode().strip()
            size = int(conn_file.readline().decode().strip())
            filepath = os.path.join(SHARED_DIR, filename)
            received = 0
            with open(filepath, 'wb') as f:
                while received < size:
                    chunk = conn.recv(min(4096, size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
            shared_files[filename] = filepath
            conn_file.write(
                f'UPLOAD_SUCCESS Received {received} bytes\n'.encode())
            conn_file.flush()
        # DOWNLOAD command
        elif command == 'DOWNLOAD':
            conn_file.write(b'READY\n')
            conn_file.flush()
            filename = conn_file.readline().decode().strip()
            if filename not in shared_files:
                conn_file.write(b'ERROR: File not found\n')
                conn_file.flush()
                return
            filepath = shared_files[filename]
            size = os.path.getsize(filepath)
            conn_file.write(f'{size}\n'.encode())
            conn_file.flush()
            ack = conn_file.readline().decode().strip()
            if ack != 'READY':
                return
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(4096)
                    if not data:
                        break
                    conn.sendall(data)
        else:
            conn_file.write(b'ERROR: Unknown command\n')
            conn_file.flush()
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn_file.close()
        conn.close()


if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Peer listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(
            target=handle_client_connection, args=(conn, addr))
        thread.daemon = True
        thread.start()
