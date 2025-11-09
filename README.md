# 🖧 Network File Sharing Server & Client

This project implements a **secure client–server file sharing system** using **C++**, **TCP sockets**, and **OpenSSL** for encryption.  
It allows authenticated users to **list, upload, and download** files between a client and a shared server directory — with AES-256-CBC encryption for all file transfers.

---

## 📁 Files Included

| File         | Description                                                                                                          |
| ------------ | -------------------------------------------------------------------------------------------------------------------- |
| `server.cpp` | Multi-threaded TCP server that handles client authentication, file listing, upload/download, and AES-256 encryption. |
| `client.cpp` | Client-side application for authentication, file listing, encrypted upload/download using password-derived key.      |
| `users.txt`  | Contains valid `username:sha256(password)` entries for authentication.                                               |
| `Makefile`   | Compilation script for building the project.                                                                         |

---

## ⚙️ Requirements

- **Operating System:** Linux / POSIX-compliant environment
- **Compiler:** `g++` or `gcc`
- **Libraries:**
  - `OpenSSL` (development headers) → install using:
    ```bash
    sudo apt install libssl-dev
    ```
  - `pthread` (for multithreading support)

---

## 🧱 Compilation

Run the following command in your project directory:

```bash
make
```
### 🚀 Running the Application
## 1️⃣ Start the Server

```bash
./server 9000 ./shared_folder
```
- 9000 → Port number
- ./shared_folder → Directory where server files are stored/shared

## 2️⃣ Start the Client

```bash
./client 127.0.0.1 9000
```
- Replace 127.0.0.1 with the server’s IP address when running on a different machine.

## 🔒 Authentication and Encryption Details


- Clients authenticate using a username and plaintext password.
- The server verifies credentials against users.txt, which stores SHA-256 password hashes.
- Once authenticated:
- Both client and server derive a 256-bit AES key using PBKDF2 (based on the password).
- All subsequent file transfers (UPLOAD/DOWNLOAD) are encrypted with AES-256-CBC.


## 📋 Supported Commands

| Command             | Description                                      |
|--------------------|--------------------------------------------------|
| `LIST`             | Lists all files available in the shared folder  |
| `UPLOAD <filename>`| Uploads a file from client to server (encrypted)|
| `DOWNLOAD <filename>`| Downloads a file from server to client (decrypted)|
| `EXIT`             | Terminates the client session                    |


## 🧩 Sample users.txt

```text
alice:e3afed0047b08059d0fada10f400c1e5
bob:5d41402abc4b2a76b9719d911017c592
```

Each entry is formatted as:
username:sha256(password)
To generate a SHA-256 hash:
```bash
echo -n "your_password" | sha256sum
```

## 🧪 Testing (Step-by-Step)

Start the server
```bash
./server 9000 ./shared_folder
```
Run the client
```bash
./client 127.0.0.1 9000
```
Login using valid credentials from users.txt.

Try commands:
- LIST
- UPLOAD test.txt
- DOWNLOAD test.txt
- EXIT

Verify:
Uploaded files appear in the shared_folder directory.
Downloaded files match the originals.

## 🧑‍💻 Author

- Ariya Ayushmita
- Wipro Training Program – Batch 4



