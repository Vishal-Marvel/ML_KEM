import socket
import pickle
import struct
from pq_box import MLKEMBox, MLDSABox, pick_mlkem_name, pick_mldsa_name

HOST = '127.0.0.1'
PORT = 5000

def recv_msg(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    data = b''
    while len(data) < msg_len:
        part = conn.recv(msg_len - len(data))
        if not part:
            return None
        data += part
    return data

def send_msg(conn, data_bytes):
    conn.sendall(struct.pack('>I', len(data_bytes)) + data_bytes)

def run_server():
    kem_name = pick_mlkem_name()
    sig_name = pick_mldsa_name()

    # Generate ML-KEM keypair
    kem_box = MLKEMBox(kem_name)
    alice_kem, alice_pk = kem_box.generate_keypair()

    # Generate ML-DSA keypair
    sig_box = MLDSABox(sig_name)
    _, sig_pk, sig_sk = sig_box.generate_keypair()

    # Sign the KEM public key
    signature = sig_box.sign(sig_sk, alice_pk)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            # Send: KEM pubkey, signature, sig pubkey
            payload = {
                "kem_pubkey": alice_pk,
                "sig_pubkey": sig_pk,
                "sig_alg": sig_name,
                "signature": signature,
            }
            send_msg(conn, pickle.dumps(payload))
            print("KEM public key + signature sent. Waiting for encrypted messages...")

            while True:
                msg_bytes = recv_msg(conn)
                if msg_bytes is None:
                    print("Client disconnected.")
                    break
                bundle = pickle.loads(msg_bytes)
                plaintext = kem_box.decrypt_with(alice_kem, bundle)
                print("Decrypted from client:", plaintext.decode(errors="replace"))
                if plaintext.strip().lower() == b"exit":
                    print("Client requested to exit.")
                    break
    print("Server shutting down.")

if __name__ == "__main__":
    run_server()
