# ML-KEM TCP Demo

This project demonstrates how to use **ML-KEM** (Kyber) post-quantum key exchange with Python to establish a shared secret and use it for symmetric encryption (AES-GCM) over a simple TCP connection.

It uses the [pyoqs / liboqs](https://github.com/open-quantum-safe/liboqs) Python bindings for ML-KEM.

## Features

- **Post-Quantum Key Encapsulation (ML-KEM):**  
  The server generates an ML-KEM keypair and shares its public key with the client.
- **AES-GCM Encryption:**  
  Both parties derive a shared AES-256 key from the ML-KEM secret using HKDF.
- **Secure TCP Messaging:**  
  The client encrypts messages with AES-GCM and sends them to the server; the server decrypts and prints them.
- **Continuous Mode:**  
  The connection stays open; you can send multiple messages until you type `exit` or stop with Ctrl+C.

## Project Structure

```
kem_box.py     # Contains MLKEMBox class and helper functions (KEM + AES logic)
kem_server.py # TCP server: generates keypair, receives and decrypts messages
kem_client.py # TCP client: connects, receives public key, encrypts and sends messages
```

## Prerequisites

- **Python 3.8+**
- [liboqs-python](https://pypi.org/project/pyoqs-sdk/) (prebuilt liboqs bindings for Python)
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies:

```bash
pip install -r req.txt
```

> **Note:** You need to install [CMAKE](https://cmake.org/download/) for this to work

## How It Works

1. **Key Setup:**
   - Server: generates ML-KEM keypair (`ML-KEM-768` by default) and sends the public key to the client.
   - Client: encapsulates a shared secret with the public key and derives an AES-GCM key.
2. **Message Encryption:**
   - Client encrypts plaintext messages using AES-GCM with the derived key.
   - The encrypted payload (KEM ciphertext + AES nonce + AES ciphertext) is sent to the server.
3. **Decryption:**
   - Server decapsulates the shared secret, derives the same AES key, and decrypts messages.

Messages are framed with a 4-byte length prefix to allow multiple encrypted messages over the same TCP connection.

## Usage

1. **Start the Server:**

   ```bash
   python kem_server.py
   ```

   The server listens on `127.0.0.1:5000` and waits for a client.

2. **Start the Client (in another terminal):**

   ```bash
   python kem_client.py
   ```

3. **Send Messages:**

   Type any message in the client terminal and press Enter. The server will decrypt and display it.

   Type `exit` to close the connection gracefully.

## Example

```
# Terminal 1 (server):
Server listening on 127.0.0.1:5000
Connected by ('127.0.0.1', 54321)
Public key sent. Waiting for encrypted messages...
Decrypted from client: Hello from client using ML-KEM!
Decrypted from client: exit
Client requested to exit.
Server shutting down.

# Terminal 2 (client):
Received server public key. Type messages to send. Type 'exit' to quit.
> Hello from client using ML-KEM!
Client exiting.
```

## Security Notes

- This demo is for **educational purposes**.  
  It omits authentication and proper session key management.
- For production, consider:
  - Using mutual authentication (server and client both generate KEM keys).
  - Authenticating the public key (e.g., certificates).
  - Integrating with TLS-like protocols.

## References

- [FIPS-203: ML-KEM (Kyber)](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org)
- [pyoqs Python bindings](https://github.com/open-quantum-safe/liboqs-python)

---

**License:** MIT (or whatever license you prefer)
