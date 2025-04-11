import os
import socket

# Configuration defaults
PEER_HOST = "127.0.0.1"
PEER_PORT = 5000


def send_command(command, extra_data=None):
    """
    Connect to the peer, send a command, and optionally extra data.
    Returns the connection object after sending the command.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((PEER_HOST, PEER_PORT))
    s.sendall(f"{command}\n".encode())
    return s


def list_files():
    try:
        conn = send_command("LIST")
        data = conn.recv(4096).decode()
        print("Shared files on peer:")
        print(data)
    except Exception as e:
        print(f"Error listing files: {e}")
    finally:
        conn.close()


def upload_file():
    file_path = input("Enter the full path of the file to upload: ").strip()
    if not os.path.isfile(file_path):
        print("File does not exist.")
        return

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    try:
        conn = send_command("UPLOAD")
        # Wait for server READY signal
        resp = conn.recv(1024).decode().strip()
        if resp != "READY":
            print("Server not ready for upload.")
            conn.close()
            return

        # Send file name
        conn.sendall(f"{file_name}\n".encode())
        # Send file size
        conn.sendall(f"{file_size}\n".encode())

        # Send file content in chunks
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                conn.sendall(chunk)

        response = conn.recv(1024).decode().strip()
        print(response)
    except Exception as e:
        print(f"Error uploading file: {e}")
    finally:
        conn.close()


def download_file():
    file_name = input("Enter the name of the file to download: ").strip()
    dest_path = input("Enter the destination path to save the file: ").strip()

    try:
        conn = send_command("DOWNLOAD")
        # Wait for server READY signal
        resp = conn.recv(1024).decode().strip()
        if resp != "READY":
            print("Server not ready for download.")
            conn.close()
            return

        # Send the file name
        conn.sendall(f"{file_name}\n".encode())
        # Receive file size or error message
        size_data = conn.recv(1024).decode().strip()
        if size_data.startswith("ERROR"):
            print(size_data)
            conn.close()
            return

        try:
            file_size = int(size_data)
        except ValueError:
            print("Invalid file size received.")
            conn.close()
            return

        # Send acknowledgment
        conn.sendall("READY\n".encode())

        received = 0
        with open(dest_path, 'wb') as f:
            while received < file_size:
                chunk = conn.recv(min(4096, file_size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
        print(f"Download complete. Received {received} bytes.")
    except Exception as e:
        print(f"Error downloading file: {e}")
    finally:
        conn.close()


def main():
    while True:
        print("\nCipherShare Client - Phase 1")
        print("1. List shared files")
        print("2. Upload a file")
        print("3. Download a file")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            list_files()
        elif choice == "2":
            upload_file()
        elif choice == "3":
            download_file()
        elif choice == "4":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")


# Configuration step at module level
host_input = input(f"Enter peer IP address (default {PEER_HOST}): ").strip()
if host_input:
    PEER_HOST = host_input
port_input = input(f"Enter peer port (default {PEER_PORT}): ").strip()
if port_input.isdigit():
    PEER_PORT = int(port_input)

if __name__ == "__main__":
    main()
