import os
import socket

PEER_HOST = '127.0.0.1'
PEER_PORT = 5000
session_token = None


def send_command(sock, command):
    if session_token:
        sock.sendall(f"{session_token}\n".encode())
    sock.sendall(f"{command}\n".encode())


def register_user():
    global session_token
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'REGISTER')
        resp = s.recv(1024).decode().strip()
        if resp != 'READY':
            print('Unable to register at this time. Please try again later.')
        else:
            s.sendall(f"{username}\n".encode())
            s.sendall(f"{password}\n".encode())
            result = s.recv(1024).decode().strip()
            if result.startswith('ERROR'):
                print('Registration failed:', result.split(':', 1)[1].strip())
            else:
                print('Registration successful! You can now log in.')
    except Exception:
        print('Could not connect to server. Please check your network and try again.')
    finally:
        s.close()


def login_user():
    global session_token
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'LOGIN')
        resp = s.recv(1024).decode().strip()
        if resp != 'LOGIN_READY':
            print('Unable to log in at this time. Please try again later.')
        else:
            s.sendall(f"{username}\n".encode())
            s.sendall(f"{password}\n".encode())
            parts = s.recv(1024).decode().strip().split()
            if parts[0] == 'LOGIN_SUCCESS':
                session_token = parts[1]
                print('Login successful!')
            else:
                error_message = ' '.join(parts[1:]) if len(
                    parts) > 1 else 'Invalid credentials.'
                print('Login failed:', error_message)
    except Exception:
        print('Could not connect to server. Please check your network and try again.')
    finally:
        s.close()


def list_files():
    if not session_token:
        print('Please log in to view shared files.')
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'LIST')
        data = s.recv(4096).decode()
        print('Shared files on server:')
        print(data)
    except Exception:
        print('Failed to retrieve file list. Please try again later.')
    finally:
        s.close()


def upload_file():
    if not session_token:
        print('You must log in before uploading files.')
        return
    filepath = input("Enter file path to upload: ").strip()
    if not os.path.isfile(filepath):
        print("File not found. Please check the path and try again.")
        return
    filename = os.path.basename(filepath)
    size = os.path.getsize(filepath)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'UPLOAD')
        resp = s.recv(1024).decode().strip()
        if resp.startswith('ERROR: Invalid session'):
            print('Session expired or invalid. Please log in again.')
            return
        if resp != 'READY':
            print('Server is not ready to receive files. Please try again later.')
            return
        s.sendall(f"{filename}\n".encode())
        s.sendall(f"{size}\n".encode())
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                s.sendall(chunk)
        result = s.recv(1024).decode().strip()
        print(result)
    except Exception:
        print('Upload failed due to a network error. Please try again.')
    finally:
        s.close()


def download_file():
    if not session_token:
        print('You must log in before downloading files.')
        return
    filename = input("Enter file name to download: ").strip()
    dest = input("Save as: ").strip()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((PEER_HOST, PEER_PORT))
        send_command(s, 'DOWNLOAD')
        resp = s.recv(1024).decode().strip()
        if resp.startswith('ERROR: Invalid session'):
            print('Session expired or invalid. Please log in again.')
            return
        if resp != 'READY':
            print('Server is not ready to send files. Please try again later.')
            return
        s.sendall(f"{filename}\n".encode())
        size_str = s.recv(1024).decode().strip()
        if size_str.startswith('ERROR'):
            print(size_str.split(':', 1)[1].strip())
            return
        try:
            total = int(size_str)
        except ValueError:
            print("Received invalid file size from server.")
            return
        s.sendall(b'READY\n')
        received = 0
        with open(dest, 'wb') as f:
            while received < total:
                chunk = s.recv(min(4096, total - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
        print(f"Downloaded {received} bytes successfully.")
    except Exception:
        print('Download failed due to a network error. Please try again.')
    finally:
        s.close()


def main():
    while True:
        print("\nCipherShare Client - Phase 2")
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
            print("Invalid option. Please choose a number between 1 and 6.")


# Configuration step at module level
host_input = input(f"Enter peer IP address (default {PEER_HOST}): ").strip()
if host_input:
    PEER_HOST = host_input
port_input = input(f"Enter peer port (default {PEER_PORT}): ").strip()
if port_input.isdigit():
    PEER_PORT = int(port_input)

if __name__ == "__main__":
    main()
