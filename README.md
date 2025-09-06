# ML-KEM, ML-DSA TCP Demo

This project demonstrates how to use **ML-KEM** (Kyber) post-quantum key exchange,  **ML-DSA** (Dilithium) post-quantum digital signatures  with Python to establish a shared secret and use it for symmetric encryption (AES-GCM) and to sign and verify messages over a simple TCP connection.

It uses the [pyoqs / liboqs](https://github.com/open-quantum-safe/liboqs) Python bindings for ML-KEM and ML-DSA algorithms.

## Features

- **Post-Quantum Digital Signatures (ML-DSA):**  
  The server generates an ML-DSA keypair and shares its public key with the client.
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
pq_box.py     # Contains MLKEMBox class and MLDSABox class and helper functions (KEM + DSA + AES logic)
pq_server.py # TCP server: generates keypair, signatures, receives and decrypts messages
pq_client.py # TCP client: connects, receives public key, encrypts, sends messages, verifies signed messages
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
   - Server: generates ML-DSA keypair (`ML-DSA-65` or `Dilithium2` by default) and sends the public key to the client.
   - Client: stores the server’s public key for signature verification.
2. **Message Signing:**
   - Server signs outgoing messages with its private key.
3. **Verification:**
   - Client verifies the signature with the server’s public key.
   - If the signature is valid, the message is trusted as authentic.

Messages are framed with a 4-byte length prefix to allow multiple encrypted messages over the same TCP connection.
## Usage

1. **Start the Server:**

   ```bash
   python pq_server.py
   ```

   The server listens on `127.0.0.1:5000` and waits for a client.

2. **Start the Client (in another terminal):**

   ```bash
   python pq_client.py
   ```

3. **Send Messages:**

   Type any message in the server terminal and press Enter.  
   The server signs it and sends both the message and signature to the client.  
   The client verifies and displays whether the signature is valid.

   Type `exit` to close the connection gracefully.


## Example

```
# Terminal 1 (server):
Server listening on 127.0.0.1:5000
Connected by ('127.0.0.1', 54321)
Public key sent. Type messages to sign and send.
> Hello from server using ML-DSA!
Message + signature sent.
> exit
Server shutting down.

# Terminal 2 (client):
Received server public key. Waiting for signed messages...
Verified message: Hello from server using ML-DSA!
Signature valid: True
Client exiting.
```


## Security Notes

- This demo is for **educational purposes**.  
  It omits authentication of the public key and secure channel setup.
- For production, consider:
  - Authenticating the server’s public key (e.g., certificates).  
  - Combining ML-DSA with ML-KEM for confidentiality + authenticity.  
  - Integrating with TLS-like protocols.

## References

- [FIPS-203: ML-KEM (Kyber)](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org)
- [pyoqs Python bindings](https://github.com/open-quantum-safe/liboqs-python)
