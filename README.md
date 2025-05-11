# CipherShare

A secure, peer-to-peer file sharing platform built in iterative phases.

---

## Dependencies

- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/) library

Install with:
```bash
pip install cryptography
```

---

## Phase 1 – Basic P2P File Sharing (Unencrypted)

**Description:**
A simple prototype where files are transferred in plaintext between peers.

**Features:**
- Peer/server (`fileshare_peer.py`):
  - Accepts file uploads and stores them in `shared_files/`.
  - Serves file downloads on request.
  - Lists available shared files.
- Client (`fileshare_client.py`):
  - **List** shared files on a peer.
  - **Upload** a file to a peer.
  - **Download** a file from a peer.

**How to Run (Phase 1):**
1. Start the peer/server:
   ```bash
   python3 fileshare_peer.py
   ```
2. In another terminal, run the client:
   ```bash
   python3 fileshare_client.py
   ```
3. Follow the on‑screen menu to list, upload, or download files.

---

## Phase 2 – User Authentication & Credential Handling

**Description:**
Adds account management and simple session handling to restrict file operations to authenticated users.

**Features:**
- **User Registration & Login:** Peers maintain a `users.json` store.
- **Password Hashing:** PBKDF2‑HMAC‑SHA256 with per‑user salts (via `crypto_utils.hash_password`).
- **Session Tokens:** 16‑byte hex tokens grant temporary access.
- **Access Control:** Only logged‑in users may upload/download/list files.

**How to Run (Phase 2):**
1. Ensure `users.json` exists (empty or pre‑populated).
2. Start the peer/server (same command as Phase 1).
3. Run the client and choose:
   - **Register new user** (menu option).
   - **Login user** (menu option).
   - Once logged in, **Upload**, **Download**, or **List** files.

---

## Phase 3 – File Encryption & Integrity Verification

**Description:**
Integrates symmetric encryption and hashing to protect confidentiality and integrity.

**Features:**
- **Symmetric Key Management:**
  - Generates or loads a 256‑bit AES key stored in `symmetric.key`.
- **File Encryption (Upload):**
  - AES‑CBC with PKCS7 padding.
  - Prepends a 16‑byte IV to the ciphertext.
- **File Decryption (Download):**
  - Splits IV + ciphertext, decrypts to recover plaintext.
- **Integrity Verification:**
  - Computes SHA‑256 of plaintext before upload.
  - Peers store and send this hash alongside encrypted blobs.
  - Clients re‑hash decrypted data and compare to expected hash.

**How to Run (Phase 3):**
1. After Phase 2 setup, ensure `symmetric.key` is generated (peer/client will create it on first run).
2. Start the peer/server:
   ```bash
   python3 fileshare_peer.py
   ```
3. Run the client:
   ```bash
   python3 fileshare_client.py
   ```
4. Authenticate (register & login), then:
   - **Upload a file**: Client encrypts and hashes automatically.
   - **Download a file**: Client decrypts and verifies hash before saving.

---

## Phase 4 – Credential Encryption, GUI, Access Control, and Discovery

**Description:**
Adds secure credential storage, a user-friendly GUI, fine-grained file sharing, and peer discovery.

**Features:**
- **Encrypted Credential Management:**
  - Stores session tokens securely in `credentials.json` using password-derived keys.
  - Auto-login prompts for password to decrypt the saved session token.

- **Enhanced Access Control:**
  - Files are associated with their uploader (`owner`).
  - Uploaders can optionally **share files with specific usernames**.
  - Only owners and authorized users can download shared files.
  - File listing respects access rights (private files hidden from others).

- **Upload Validation:**
  - Empty files (0 KB) are rejected at both CLI and GUI level.

- **Peer Discovery:**
  - Peers respond to UDP broadcast `DISCOVER` messages with their host/port.
  - CLI client auto-selects the first discovered peer.

- **GUI Support (Tkinter/CTk):**
  - Graphical interface to:
    - Login/Register
    - Upload and Download files
    - List available files
    - Share files with specific users
    - Logout and clear saved credentials
  - Password fields are hidden; logs and feedback shown in real-time.

**How to Run (Phase 4):**

### Command-Line Mode:
1. Start peer/server:
   ```bash
   python3 fileshare_peer.py
   ```
2. Run client:
   ```bash
   python3 fileshare_client.py
   ```

### GUI Mode:
1. Start GUI client:
   ```bash
   python3 fileshare_gui.py
   ```

**Note:** Ensure `cryptography` and `customtkinter` are installed.

## 📽️ Demo Video

To see CipherShare in action, check out our full walkthrough on YouTube:

**YouTube Demo:** [https://youtu.be/IpV2XJ3_X0Y](https://youtu.be/IpV2XJ3_X0Y)

The video demonstrates:
- CLI and GUI login/logout
- Secure file upload and download
- File sharing with specific users
- Peer discovery and encryption validation

