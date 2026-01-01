import os
from dataclasses import dataclass
from typing import Tuple

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
#Params for argon2id key derivation
# control how expensive it is to brute-force the master password
class KDFParams:
    time_cost: int = 3
    memory_cost: int = 65536  # KiB (64 MB)
    parallelism: int = 1
    hash_len: int = 32
    salt_len: int = 16

#derive a fixed-length encryption key from users master password
#argon2id used as it is memory-hard
#slower hash thereofre more expensive than a fast hash
def derive_key(master_password: str, salt: bytes, params: KDFParams) -> bytes:
    if not master_password:
        raise ValueError("Master password cannot be empty.")
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,  # Argon2id recommended variant for password hashing/kdf
    )

#encrypt bytes using AES-GCM

#returns (nonce, ciphertext) ciphertext includes the authentication tag
#tag ised to allow tamper detection
def encrypt_bytes(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    #standard AESGCM nonce size
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext

#decrypts AESGCM data and verifies integrity
#exeption raised if key is wrong or ciphertext was tampered with
def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)