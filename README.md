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

## Next Steps

Phase 4 (planned):
- Stronger KDFs (Argon2),
- Client‑side encrypted credential storage,
- Enhanced P2P discovery (chunking, distributed index),
- Fine‑grained access control.

