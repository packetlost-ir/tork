import os
import traceback
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def generate_ephemeral_keypair() -> tuple[x25519.X25519PrivateKey, bytes]:
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_bytes

def derive_shared_key(private_key: x25519.X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_pub_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_pub_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"tork-e2ee-salt-v1",
        info=b"tork-handshake",
    ).derive(shared_secret)
    return derived_key

def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(key: bytes, payload: bytes) -> bytes:
    if len(payload) < 12:
        raise ValueError("Payload too short for nonce and ciphertext.")
    nonce = payload[:12]
    ciphertext = payload[12:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, None)
