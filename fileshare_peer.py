import os
import socket
import threading
import json
import crypto_utils
import secrets

# Constants
HOST = '0.0.0.0'
PORT = 5000
SHARED_DIR = "shared_files"
USERS_FILE = "users.json"
CHUNK_SIZE = 1024 * 1024  # 1MB
SESSIONS_FILE = "sessions.json"

# Global state
sessions = {}
shared_files = {}
SYMM_KEY = crypto_utils.get_symmetric_key()

# Ensure shared directory exists
os.makedirs(SHARED_DIR, exist_ok=True)

# Helper functions
def load_users() -> dict:
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users: dict) -> None:
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def load_sessions() -> dict:
    if os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_sessions(sessions: dict) -> None:
    with open(SESSIONS_FILE, "w") as f:
        json.dump(sessions, f, indent=4)

# Initialize sessions
sessions = load_sessions()

# Main functionality
def handle_client_connection(conn: socket.socket, addr) -> None:
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
                    'hashed_password': hashed.hex(),
                    'salt': salt.hex()
                }
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
                save_sessions(sessions)

                salt_hex = stored['salt']
                conn_file.write(f'LOGIN_SUCCESS {token} {salt_hex}\n'.encode())

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

        if command == 'LIST':
            # LIST command: send filenames
            file_list = '\n'.join(shared_files.keys()) or 'No files available.'
            conn_file.write(f'{file_list}\n'.encode())
            conn_file.flush()

        elif command == 'UPLOAD':
            try:
                conn_file.write(b'READY\n')
                conn_file.flush()

                filename = conn_file.readline().decode().strip()
                print(f"[DEBUG] Got filename: {filename}")
                enc_size_str = conn_file.readline().decode().strip()
                print(f"[DEBUG] Got enc_size string: {enc_size_str}")
                plaintext_hash = conn_file.readline().decode().strip()
                print(f"[DEBUG] Got hash: {plaintext_hash}")

                if not filename or not enc_size_str or not plaintext_hash:
                    conn_file.write(b'ERROR: Missing metadata\n')
                    conn_file.flush()
                    print("[ERROR] Missing metadata")
                    return

                try:
                    enc_size = int(enc_size_str)
                except ValueError:
                    conn_file.write(b'ERROR: Invalid file size\n')
                    conn_file.flush()
                    print("[ERROR] Invalid file size")
                    return

                print(f"[DEBUG] Receiving {enc_size} bytes for {filename}")
                filepath = os.path.join(SHARED_DIR, filename)
                received = 0

                with open(filepath, 'wb') as f:
                    while received < enc_size:
                        chunk = conn_file.read(min(CHUNK_SIZE, enc_size - received))
                        if not chunk:
                            print("[ERROR] Connection lost or client stopped sending data.")
                            break
                        f.write(chunk)
                        received += len(chunk)
                        print(f"[DEBUG] Received {len(chunk)} bytes (total {received}/{enc_size})")

                if received != enc_size:
                    print(f"[ERROR] Incomplete file: expected {enc_size}, got {received}")
                    conn_file.write(f"ERROR: Incomplete file received ({received}/{enc_size})\n".encode())
                    conn_file.flush()
                    return

                shared_files[filename] = {'path': filepath, 'hash': plaintext_hash}
                conn_file.write(f'UPLOAD_SUCCESS Received {received} bytes\n'.encode())
                conn_file.flush()
                print(f"[DEBUG] Upload success: {filename} ({received} bytes)")

            except Exception as e:
                print(f"[ERROR] Exception during upload: {e}")
                conn_file.write(b'ERROR: Upload failed\n')
                conn_file.flush()


        elif command == 'DOWNLOAD':
            # DOWNLOAD command: send expected hash and encrypted file
            conn_file.write(b'READY\n')
            conn_file.flush()
            filename = conn_file.readline().decode().strip()
            if filename not in shared_files:
                conn_file.write(b'ERROR: File not found\n')
                conn_file.flush()
                return
            meta = shared_files[filename]
            plaintext_hash = meta['hash']
            filepath = meta['path']
            enc_size = os.path.getsize(filepath)
            conn_file.write(f'{plaintext_hash}\n'.encode())
            conn_file.write(f'{enc_size}\n'.encode())
            conn_file.flush()
            ack = conn_file.readline().decode().strip()
            if ack != 'READY':
                return
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    conn.sendall(chunk)

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
            target=handle_client_connection,
            args=(conn, addr),
            daemon=True
        )
        thread.start()