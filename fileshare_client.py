import os
import socket
import crypto_utils

# Configuration: default peer host/port and symmetric key
PEER_HOST = '127.0.0.1'
PEER_PORT = 5000
session_token = None
# Load or generate symmetric key for file encryption
SYMM_KEY = crypto_utils.get_symmetric_key()


def send_command(sock: socket.socket, command: str) -> None:
    """Send session token (if any) and command to the peer."""
    if session_token:
        sock.sendall(f"{session_token}\n".encode())
    sock.sendall(f"{command}\n".encode())


def register_user() -> None:
    """Register a new user by sending username/password to peer."""
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((PEER_HOST, PEER_PORT))
            send_command(s, 'REGISTER')
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
    """Authenticate and obtain a session token from the peer."""
    global session_token
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((PEER_HOST, PEER_PORT))
            send_command(s, 'LOGIN')
            resp = s.recv(1024).decode().strip()
            if resp != 'LOGIN_READY':
                print('Unable to log in at this time. Please try again later.')
                return
            s.sendall(f"{username}\n".encode())
            s.sendall(f"{password}\n".encode())
            parts = s.recv(1024).decode().strip().split()
            if parts[0] == 'LOGIN_SUCCESS':
                session_token = parts[1]
                print('Login successful!')
            else:
                error_msg = ' '.join(parts[1:]) if len(
                    parts) > 1 else 'Invalid credentials.'
                print('Login failed:', error_msg)
        except Exception:
            print('Could not connect to server. Please check your network and try again.')


def list_files() -> None:
    """Retrieve and display list of shared files from peer."""
    if not session_token:
        print('Please log in to view shared files.')
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((PEER_HOST, PEER_PORT))
            send_command(s, 'LIST')
            data = s.recv(8192).decode()
            print('Shared files on server:')
            print(data)
        except Exception:
            print('Failed to retrieve file list. Please try again later.')


def upload_file() -> None:
    """Encrypt, hash, and upload a file to the peer."""
    if not session_token:
        print('You must log in before uploading files.')
        return
    filepath = input("Enter file path to upload: ").strip()
    if not os.path.isfile(filepath):
        print('File not found. Please check the path and try again.')
        return
    filename = os.path.basename(filepath)
    # Compute plaintext SHA-256 hash
    plaintext_hash = crypto_utils.hash_file(filepath)
    # Read entire file and encrypt
    with open(filepath, 'rb') as f:
        data = f.read()
    iv, ciphertext = crypto_utils.encrypt_bytes(data, SYMM_KEY)
    enc_payload = iv + ciphertext
    enc_size = len(enc_payload)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((PEER_HOST, PEER_PORT))
            send_command(s, 'UPLOAD')
            resp = s.recv(1024).decode().strip()
            if resp.startswith('ERROR'):
                print(resp)
                return
            if resp != 'READY':
                print('Server is not ready to receive files. Please try again later.')
                return
            # Send metadata: filename, encrypted size, plaintext hash
            s.sendall(f"{filename}\n".encode())
            s.sendall(f"{enc_size}\n".encode())
            s.sendall(f"{plaintext_hash}\n".encode())
            # Send encrypted payload
            s.sendall(enc_payload)
            result = s.recv(1024).decode().strip()
            print(result)
        except Exception:
            print('Upload failed due to a network error. Please try again.')


def download_file() -> None:
    """Download, decrypt, and verify integrity of a file from the peer."""
    if not session_token:
        print('You must log in before downloading files.')
        return
    filename = input("Enter file name to download: ").strip()
    dest = input("Save as: ").strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((PEER_HOST, PEER_PORT))
            send_command(s, 'DOWNLOAD')
            resp = s.recv(1024).decode().strip()
            if resp.startswith('ERROR'):
                print(resp)
                return
            if resp != 'READY':
                print('Server is not ready to send files. Please try again later.')
                return
            # Request the file
            s.sendall(f"{filename}\n".encode())
            # Use file-like wrapper for header lines
            sock_file = s.makefile('rwb')
            expected_hash = sock_file.readline().decode().strip()
            size_str = sock_file.readline().decode().strip()
            try:
                total = int(size_str)
            except ValueError:
                print('Received invalid file size from server.')
                return
            # Acknowledge readiness
            s.sendall(b'READY\n')
            # Read encrypted payload
            received = 0
            buf = bytearray()
            while received < total:
                chunk = s.recv(min(4096, total - received))
                if not chunk:
                    break
                buf.extend(chunk)
                received += len(chunk)
            # Close the file wrapper
            sock_file.close()
            # Separate IV and ciphertext
            iv = bytes(buf[:16])
            ciphertext = bytes(buf[16:])
            # Decrypt and verify
            plaintext = crypto_utils.decrypt_bytes(iv, ciphertext, SYMM_KEY)
            actual_hash = crypto_utils.hash_bytes(plaintext)
            if actual_hash != expected_hash:
                print('Integrity check failed! File may be corrupted.')
                return
            # Write to disk
            with open(dest, 'wb') as f:
                f.write(plaintext)
            print(f"Downloaded and verified {received} bytes successfully.")
        except Exception:
            print('Download failed due to a network error. Please try again.')


def main() -> None:
    """Main menu loop for the CipherShare client."""
    global PEER_HOST, PEER_PORT
    # Allow overriding host/port on startup
    host_input = input(
        f"Enter peer IP address (default {PEER_HOST}): ").strip()
    if host_input:
        PEER_HOST = host_input
    port_input = input(f"Enter peer port (default {PEER_PORT}): ").strip()
    if port_input.isdigit():
        PEER_PORT = int(port_input)

    while True:
        print("\nCipherShare Client - Phase 3")
        print("1. List shared files")
        print("2. Upload a file")
        print("3. Download a file")
        print("4. Login user")
        print("5. Register new user")
        print("6. Exit")
        choice = input("Choice: ").strip()
        if choice == '1':
            list_files()
        elif choice == '2':
            upload_file()
        elif choice == '3':
            download_file()
        elif choice == '4':
            login_user()
        elif choice == '5':
            register_user()
        elif choice == '6':
            print('Goodbye!')
            break
        else:
            print("Invalid option. Please choose 1-6.")


if __name__ == "__main__":
    main()
