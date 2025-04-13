import os
import socket
import threading
import json
import crypto_utils 

# Configuration
HOST = '0.0.0.0'
PORT = 5000
SHARED_DIR = "shared_files"

# File to store user data
USERS_FILE = "users.json"  

def load_users():
    """Load user data from JSON file. Returns a dictionary."""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {} 

def save_users(users):
    """Save user data to JSON file."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)  
        
        
def handle_register(conn):
    try:
       
        conn.sendall("READY\n".encode())
        
        # Receive username and password in one go
        data = conn.recv(1024).decode().strip().split('\n')
        if len(data) < 2:
            conn.sendall("ERROR: Need username and password\n".encode())
            return
            
        username = data[0]
        password = data[1]

        users = load_users()
        if username in users:
            conn.sendall("ERROR: Username exists\n".encode())
            return

        hashed_password, salt = crypto_utils.hash_password(password)
        users[username] = {"hashed_password": hashed_password, "salt": salt}
        save_users(users)
        conn.sendall("REGISTER_SUCCESS\n".encode())

    except Exception as e:
        conn.sendall(f"REGISTER_ERROR: {e}\n".encode())
        


# Ensure the shared files directory exists
if not os.path.exists(SHARED_DIR):
    os.makedirs(SHARED_DIR)

# In-memory shared files list: keys are filenames, values are full paths.
shared_files = {}


def handle_upload(conn):
    try:
        # Send READY signal to client
        conn.sendall("READY\n".encode())

        # Receive file name
        file_name = conn.recv(1024).decode().strip()
        if not file_name:
            conn.sendall("ERROR: No filename received\n".encode())
            return

        # Receive file size (as string)
        file_size_str = conn.recv(1024).decode().strip()
        try:
            file_size = int(file_size_str)
        except ValueError:
            conn.sendall("ERROR: Invalid file size\n".encode())
            return

        # Define file path
        file_path = os.path.join(SHARED_DIR, file_name)
        received = 0

        # Open file to write bytes
        with open(file_path, 'wb') as f:
            while received < file_size:
                chunk = conn.recv(min(4096, file_size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)

        # Update shared files list
        shared_files[file_name] = file_path
        conn.sendall(f"UPLOAD SUCCESS: Received {received} bytes\n".encode())
    except Exception as e:
        conn.sendall(f"UPLOAD ERROR: {e}\n".encode())


def handle_download(conn):
    try:
        # Send READY signal to client
        conn.sendall("READY\n".encode())

        # Receive file name
        file_name = conn.recv(1024).decode().strip()
        if file_name not in shared_files:
            conn.sendall("ERROR: File not found\n".encode())
            return

        file_path = shared_files[file_name]
        file_size = os.path.getsize(file_path)
        # Send file size to client
        conn.sendall(f"{file_size}\n".encode())

        # Wait for client acknowledgment
        ack = conn.recv(1024).decode().strip()
        if ack != "READY":
            return

        # Send the file content
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                conn.sendall(data)
    except Exception as e:
        conn.sendall(f"DOWNLOAD ERROR: {e}\n".encode())


def handle_list(conn):
    try:
        file_list = "\n".join(shared_files.keys())
        if not file_list:
            file_list = "No files available."
        conn.sendall(file_list.encode())
    except Exception as e:
        conn.sendall(f"LIST ERROR: {e}\n".encode())

def handle_client_connection(conn, addr):
    print(f"Accepted connection from {addr}")
    try:
        
        command = conn.recv(1024).decode().strip().upper()
        if not command:
            print(f"Client {addr} disconnected without sending command")
            return
            
        print(f"Processing command: {command} from {addr}")

        if command == "REGISTER":
            # Send acknowledgement
            conn.sendall("REGISTER_ACK\n".encode())
            
            # Receive credentials (username\npassword)
            creds = conn.recv(1024).decode().strip().split('\n')
            if len(creds) != 2:
                conn.sendall("ERROR: Invalid format. Expected username\\npassword\n".encode())
                return
                
            username, password = creds[0], creds[1]
            print(f"Registration attempt for user: {username}")
            
            # Process registration
            users = load_users()
            if username in users:
                conn.sendall("ERROR: Username already exists\n".encode())
            else:
                try:
                    hashed_pw, salt = crypto_utils.hash_password(password)
                    users[username] = {
                        'hashed_password': hashed_pw.hex(),
                        'salt': salt.hex()
                    }
                    save_users(users)
                    conn.sendall("REGISTER_SUCCESS\n".encode())
                    print(f"Registered new user: {username}")
                except Exception as e:
                    conn.sendall(f"ERROR: Registration failed ({str(e)})\n".encode())
                    print(f"Registration error for {username}: {e}")

        elif command == "UPLOAD":
            handle_upload(conn)
            
        elif command == "DOWNLOAD":
            handle_download(conn)
            
        elif command == "LIST":
            handle_list(conn)
            
        else:
            conn.sendall("ERROR: Unknown command\n".encode())
            print(f"Unknown command from {addr}: {command}")

    except ConnectionResetError:
        print(f"Client {addr} disconnected abruptly")
    except Exception as e:
        print(f"Error handling client {addr}: {str(e)}")
        try:
            conn.sendall(f"ERROR: {str(e)}\n".encode())
        except:
            pass
    finally:
        try:
            conn.close()
            print(f"Closed connection for {addr}")
        except:
            pass
        
        

def start_peer():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Peer listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(
            target=handle_client_connection, args=(conn, addr))
        client_thread.daemon = True
        client_thread.start()


if __name__ == "__main__":
    start_peer()
