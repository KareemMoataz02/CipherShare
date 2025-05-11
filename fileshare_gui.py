import os
import socket
import json
import customtkinter as ctk
from tkinter import filedialog
import crypto_utils
import tkinter as tk


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


def discover_peer(timeout=2.0):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp.settimeout(timeout)
    udp.sendto(b'DISCOVER', ('<broadcast>', BROADCAST_PORT))
    try:
        data, _ = udp.recvfrom(1024)
        info = json.loads(data.decode())
        return info['host'], info['port']
    except Exception:
        return PEER_HOST, PEER_PORT


# ========== GUI Application ==========
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class CipherShareGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CipherShare")
        self.geometry("760x540")

        # Auto-discover peer
        global PEER_HOST, PEER_PORT
        host, port = discover_peer()
        PEER_HOST, PEER_PORT = host, port

        # Build UI
        self.build_auth_frame()
        self.build_ops_frame()
        self.build_output_frame()

    def build_auth_frame(self):
        frm = ctk.CTkFrame(self, corner_radius=12)
        frm.pack(fill='x', pady=10, padx=10)

        self.entry_user = ctk.CTkEntry(
            frm, placeholder_text="Username", corner_radius=8)
        self.entry_user.grid(row=0, column=0, padx=10, pady=10, sticky='ew')
        self.entry_pass = ctk.CTkEntry(
            frm, placeholder_text="Password", show='*', corner_radius=8)
        self.entry_pass.grid(row=0, column=1, padx=10, pady=10, sticky='ew')

        btn_reg = ctk.CTkButton(frm, text="Register",
                                corner_radius=20, command=self.register)
        btn_reg.grid(row=0, column=2, padx=10)
        btn_login = ctk.CTkButton(
            frm, text="Login", corner_radius=20, command=self.login)
        btn_login.grid(row=0, column=3, padx=10)

        frm.grid_columnconfigure(0, weight=1)
        frm.grid_columnconfigure(1, weight=1)

    def build_ops_frame(self):
        frm = ctk.CTkFrame(self, corner_radius=12)
        frm.pack(fill='x', pady=10, padx=10)

        self.list_btn = ctk.CTkButton(
            frm, text="List Files", corner_radius=20, command=self.list_files)
        self.list_btn.grid(row=0, column=0, padx=10, pady=5)

        self.upload_path = ctk.CTkEntry(
            frm, placeholder_text="Select file to upload...", corner_radius=8)
        self.upload_path.grid(row=1, column=0, columnspan=2,
                              padx=10, pady=5, sticky='ew')
        btn_browse = ctk.CTkButton(
            frm, text="Browse", corner_radius=20, command=self.browse_upload)
        btn_browse.grid(row=1, column=2, padx=10)
        btn_upload = ctk.CTkButton(
            frm, text="Upload", corner_radius=20, command=self.upload_file)
        btn_upload.grid(row=1, column=3, padx=10)

        self.share_file_entry = ctk.CTkEntry(
            frm, placeholder_text="Filename to share", corner_radius=8)
        self.share_file_entry.grid(
            row=2, column=0, padx=10, pady=5, sticky='ew')
        self.share_users_entry = ctk.CTkEntry(
            frm, placeholder_text="Users (comma-separated)", corner_radius=8)
        self.share_users_entry.grid(
            row=2, column=1, padx=10, pady=5, sticky='ew')
        btn_share = ctk.CTkButton(
            frm, text="Share", corner_radius=20, command=self.share_file)
        btn_share.grid(row=2, column=2, padx=10)

        self.download_file_entry = ctk.CTkEntry(
            frm, placeholder_text="Filename to download", corner_radius=8)
        self.download_file_entry.grid(
            row=3, column=0, padx=10, pady=5, sticky='ew')
        self.download_dest_entry = ctk.CTkEntry(
            frm, placeholder_text="Save as...", corner_radius=8)
        self.download_dest_entry.grid(
            row=3, column=1, padx=10, pady=5, sticky='ew')
        btn_browse2 = ctk.CTkButton(
            frm, text="Browse", corner_radius=20, command=self.browse_download)
        btn_browse2.grid(row=3, column=2, padx=10)
        btn_download = ctk.CTkButton(
            frm, text="Download", corner_radius=20, command=self.download_file)
        btn_download.grid(row=3, column=3, padx=10)
        
        logout_button = ctk.CTkButton(frm, text="Logout", corner_radius=20, command=self.logout)
        logout_button.grid(row=4, column=0, padx=10, pady=10)


        for i in range(4):
            frm.grid_columnconfigure(i, weight=1)

    def build_output_frame(self):
        frm = ctk.CTkFrame(self, corner_radius=12)
        frm.pack(fill='both', expand=True, pady=10, padx=10)

        self.txt_output = ctk.CTkTextbox(frm, corner_radius=8)
        self.txt_output.pack(fill='both', expand=True, padx=10, pady=10)
    # ========== UI Actions ==========

    def log(self, message: str):
        self.txt_output.insert(tk.END, message + "\n")
        self.txt_output.see(tk.END)

    def browse_upload(self):
        path = filedialog.askopenfilename()
        if path:
            self.upload_path.delete(0, tk.END)
            self.upload_path.insert(0, path)

    def browse_download(self):
        dest = filedialog.asksaveasfilename(defaultextension="*")
        if dest:
            self.download_dest_entry.delete(0, tk.END)
            self.download_dest_entry.insert(0, dest)

    def register(self):
        uname = self.entry_user.get().strip()
        pwd = self.entry_pass.get().strip()
        if not uname or not pwd:
            self.log("Both username and password are required.")
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((PEER_HOST, PEER_PORT))
                send_command(s, 'REGISTER')
                if s.recv(1024).decode().strip() != 'READY':
                    self.log("Register failed: server not ready.")
                    return
                s.sendall(f"{uname}\n".encode())
                s.sendall(f"{pwd}\n".encode())
                res = s.recv(1024).decode().strip()
                self.log(res)
        except Exception as e:
            self.log(f"Error: {e}")

    def login(self):
        global session_token
        uname = self.entry_user.get().strip()
        pwd = self.entry_pass.get().strip()
        if not uname or not pwd:
            self.log("Enter username and password to login.")
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((PEER_HOST, PEER_PORT))
                send_command(s, 'LOGIN')
                if s.recv(1024).decode().strip() != 'LOGIN_READY':
                    self.log("Login failed: server not ready.")
                    return
                s.sendall(f"{uname}\n".encode())
                s.sendall(f"{pwd}\n".encode())
                parts = s.recv(1024).decode().strip().split()
                if parts[0] == 'LOGIN_SUCCESS':
                    session_token = parts[1]
                    self.log("Login successful. Welcome!")
                else:
                    self.log("Login failed: " + ' '.join(parts[1:]))
        except Exception as e:
            self.log(f"Error: {e}")

    def list_files(self):
        if not session_token:
            self.log("Please login first to list files.")
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((PEER_HOST, PEER_PORT))
                send_command(s, 'LIST')
                data = s.recv(8192).decode().strip()
                self.log("Files:\n" + data)
        except Exception as e:
            self.log(f"Error: {e}")

    def upload_file(self):
        if not session_token:
            self.log("Login required to upload files.")
            return

        path = self.upload_path.get().strip()
        if not path or not os.path.isfile(path):
            self.log("Valid file path required to upload.")
            return

        if os.path.getsize(path) == 0:
            self.log("Cannot upload an empty file.")
            return

        plaintext_hash = crypto_utils.hash_file(path)
        with open(path, 'rb') as f:
            data = f.read()
        iv, ct = crypto_utils.encrypt_bytes(data, SYMM_KEY)
        payload = iv + ct
        size = len(payload)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((PEER_HOST, PEER_PORT))
                send_command(s, 'UPLOAD')
                if s.recv(1024).decode().strip() != 'READY':
                    self.log("Upload failed: server not ready.")
                    return
                fname = os.path.basename(path)
                s.sendall(f"{fname}\n".encode())
                s.sendall(f"{size}\n".encode())
                s.sendall(f"{plaintext_hash}\n".encode())
                s.sendall(payload)
                res = s.recv(1024).decode().strip()
                self.log(res)
        except Exception as e:
            self.log(f"Error: {e}")


    def share_file(self):
        if not session_token:
            self.log("Login required to share files.")
            return
        fname = self.share_file_entry.get().strip()
        users = self.share_users_entry.get().strip()
        if not fname or not users:
            self.log("Filename and user list required to share.")
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((PEER_HOST, PEER_PORT))
                send_command(s, 'SHARE')
                s.sendall(f"{fname}\n".encode())
                s.sendall(f"{users}\n".encode())
                res = s.recv(1024).decode().strip()
                self.log(res)
        except Exception as e:
            self.log(f"Error: {e}")

    def download_file(self):
        if not session_token:
            self.log("Login required to download files.")
            return

        fname = self.download_file_entry.get().strip()
        dest = self.download_dest_entry.get().strip()
        if not fname or not dest:
            self.log("Filename and destination required to download.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((PEER_HOST, PEER_PORT))
                send_command(s, 'DOWNLOAD')

                if s.recv(1024).decode().strip() != 'READY':
                    self.log("Download failed: server not ready.")
                    return

                s.sendall(f"{fname}\n".encode())
                sf = s.makefile('rwb')

         
                exp = sf.readline().decode().strip()
                if exp.startswith("ERROR"):
                    self.log(exp)
                    return

              
                size_line = sf.readline().decode().strip()
                if size_line.startswith("ERROR"):
                    self.log(size_line)
                    return

                try:
                    total = int(size_line)
                except ValueError:
                    self.log(f"Invalid size received: {size_line}")
                    return

                s.sendall(b'READY\n')

                buf = bytearray()
                recv = 0
                while recv < total:
                    chunk = s.recv(min(CHUNK_SIZE, total - recv))
                    if not chunk:
                        break
                    buf.extend(chunk)
                    recv += len(chunk)

                sf.close()
                iv, ct = buf[:16], buf[16:]
                pt = crypto_utils.decrypt_bytes(iv, ct, SYMM_KEY)
                actual = crypto_utils.hash_bytes(pt)

                if actual != exp:
                    self.log("Integrity check failed.")
                    return

                with open(dest, 'wb') as f:
                    f.write(pt)

                self.log(f"Download saved to {dest}.")

        except Exception as e:
            self.log(f"Error: {e}")

            
    def logout(self):
        global session_token
        session_token = None

        # Clear login fields
        self.entry_user.delete(0, tk.END)
        self.entry_pass.delete(0, tk.END)

        # Clear file input fields using correct widget names
        self.upload_path.delete(0, tk.END)
        self.download_file_entry.delete(0, tk.END)
        self.download_dest_entry.delete(0, tk.END)
        self.share_file_entry.delete(0, tk.END)
        self.share_users_entry.delete(0, tk.END)

        # Clear log area
        self.txt_output.delete("1.0", tk.END)

        # Delete credentials
        try:
            os.remove("credentials.json")
            self.log("You have been logged out.")
        except FileNotFoundError:
            self.log("No saved login session found.")


if __name__ == '__main__':
    app = CipherShareGUI()
    app.mainloop()
