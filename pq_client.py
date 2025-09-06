import socket
import pickle
import struct
from pq_box import MLKEMBox, MLDSABox, pick_mlkem_name

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

def run_client():
    kem_name = pick_mlkem_name()
    kem_box = MLKEMBox(kem_name)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Receive server KEM pubkey + signature
        payload = pickle.loads(recv_msg(s))

        sig_box = MLDSABox(payload["sig_alg"])
        if not sig_box.verify(payload["sig_pubkey"], payload["kem_pubkey"], payload["signature"]):
            raise RuntimeError("❌ Server KEM public key signature invalid! Aborting.")

        print("✅ Verified server KEM public key. Type messages to send. Type 'exit' to quit.")
        server_pk = payload["kem_pubkey"]

        while True:
            user_input = input("> ")
            bundle = kem_box.encrypt_for(server_pk, user_input.encode())
            send_msg(s, pickle.dumps(bundle))
            if user_input.strip().lower() == "exit":
                break
    print("Client exiting.")

if __name__ == "__main__":
    run_client()
