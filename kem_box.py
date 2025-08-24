import os
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def pick_mlkem_name():
    prefer = ["ML-KEM-768", "ML-KEM-512", "ML-KEM-1024", "Kyber768", "Kyber512", "Kyber1024"]
    enabled = set(oqs.get_enabled_kem_mechanisms())
    for name in prefer:
        if name in enabled:
            return name
    raise RuntimeError("No ML-KEM/Kyber mechanism found in oqs build.")

def kdf_aes_key(shared_secret: bytes, context: bytes = b"ml-kem-aesgcm-v1") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context)
    return hkdf.derive(shared_secret)

class MLKEMBox:
    def __init__(self, kem_name: str):
        self.kem_name = kem_name

    def generate_keypair(self):
        kem = oqs.KeyEncapsulation(self.kem_name)
        pk = kem.generate_keypair()
        return kem, pk

    def encrypt_for(self, recipient_public_key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
        with oqs.KeyEncapsulation(self.kem_name) as sender_kem:
            ct_kem, ss = sender_kem.encap_secret(recipient_public_key)
        aes_key = kdf_aes_key(ss)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return {"kem_ciphertext": ct_kem, "nonce": nonce, "ciphertext": ct, "aad": aad}

    # <- annotation removed here
    def decrypt_with(self, recipient_kem, bundle: dict) -> bytes:
        ss = recipient_kem.decap_secret(bundle["kem_ciphertext"])
        aes_key = kdf_aes_key(ss)
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(bundle["nonce"], bundle["ciphertext"], bundle.get("aad", b""))

if __name__ == "__main__":
    kem_name = pick_mlkem_name()
    box = MLKEMBox(kem_name)

    alice_kem, alice_pk = box.generate_keypair()

    message = b"hello from the post-quantum future \xf0\x9f\x8c\x9d"
    aad = b"header-metadata-v1"

    bundle = box.encrypt_for(alice_pk, message, aad=aad)

    recovered = box.decrypt_with(alice_kem, bundle)
    assert recovered == message
    print("Decryption OK; message =", recovered.decode(errors="replace"))
