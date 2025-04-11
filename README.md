# CipherShare: Phase 1 – Basic P2P File Sharing (Unencrypted)

This is a basic prototype for the CipherShare project. In this phase, the system supports:
- A peer/server that accepts file uploads, serves file downloads, and lists the files available.
- A client that allows users to:
  - **List** available shared files.
  - **Upload** a file to a peer.
  - **Download** a file from a peer.

**How to Run:**

1. **Peer/Server:**
   - Run `fileshare_peer.py` on the designated host (e.g., on localhost).
   - The server listens on a fixed port (default is 5000) and stores uploaded files in the `shared_files` directory.

   ```bash
   python fileshare_peer.py
