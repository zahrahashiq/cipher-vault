import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

from vault_crypto import KDFParams, derive_key, encrypt_bytes, decrypt_bytes

#path to encrypted vault file on disk (local-only demo storage)
VAULT_PATH = Path("vault.enc")

#base 64 encode bytes so they can be stored safely in json
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

#decode base 64 string to raw bytes
def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

#return true if the vault file already exists
def vault_exists() -> bool:
    return VAULT_PATH.exists()

#create new vault file on disk.
#format is a json envelope containing
    #-kdf params + salt
    #AESGCM nonce + ciphertext (encrypted payload)
#the payload is JSON encrypted as bytes
def create_new_vault(master_password: str) -> None:
    params = KDFParams()
    
    #salt ensures the same password derives different keys for different vaults
    salt = os.urandom(params.salt_len)
    
    #derive a strong symmetric key from the master password
    key = derive_key(master_password, salt, params)

    #initial empty vault payload which is stored encrypted
    data = {"entries": []}
    plaintext = json.dumps(data).encode("utf-8")
    
    #encrypt
    nonce, ciphertext = encrypt_bytes(key, plaintext)

    #vault: safe meta data and encrypted payload
    vault_obj = {
        "version": 1,
        "kdf": {
            "algo": "argon2id",
            "time_cost": params.time_cost,
            "memory_cost": params.memory_cost,
            "parallelism": params.parallelism,
            "salt": _b64e(salt),
        },
        "crypto": {
            "algo": "aesgcm",
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        },
    }

    #Write json in a readable way
    VAULT_PATH.write_text(json.dumps(vault_obj, indent=2), encoding="utf-8")

#read vault envelope (json metadata and ciphertext)
def _read_vault_obj() -> Dict[str, Any]:
    return json.loads(VAULT_PATH.read_text(encoding="utf-8"))

#write vault envelope back to the disk (overwrite existing file)
def _write_vault_obj(vault_obj: Dict[str, Any]) -> None:
    VAULT_PATH.write_text(json.dumps(vault_obj, indent=2), encoding="utf-8")


#unlock vault with master password
#returns the derived key in bytes
    #used to encrypt/decrypt in the session
#decrypted data is the vaults contents 
#flags raised if 
    #the password is wrong
    #the vault data has been modified or tampered with
def unlock_with_password(master_password: str) -> Tuple[bytes, Dict[str, Any]]:
    vault_obj = _read_vault_obj()

    #extract KDF settings from vault file so same params are reused
    kdf = vault_obj["kdf"]
    salt = _b64d(kdf["salt"])
    params = KDFParams(
        time_cost=int(kdf["time_cost"]),
        memory_cost=int(kdf["memory_cost"]),
        parallelism=int(kdf["parallelism"]),
    )

    #derive a key from the password and stored params/salt
    key = derive_key(master_password, salt, params)

    #decrypt payload 
    crypto = vault_obj["crypto"]
    nonce = _b64d(crypto["nonce"])
    ciphertext = _b64d(crypto["ciphertext"])

    #AESGCM verifies intergrity
    #raises on wrong key or signs of tampering
    plaintext = decrypt_bytes(key, nonce, ciphertext)  # raises if wrong password/tampered
    data = json.loads(plaintext.decode("utf-8"))
    return key, data

#Load and decrypt vault contents using the derived key
#Used after user has unlocked the vault and the key is server-side
def load_with_key(key: bytes) -> Dict[str, Any]:
    vault_obj = _read_vault_obj()
    crypto = vault_obj["crypto"]
    nonce = _b64d(crypto["nonce"])
    ciphertext = _b64d(crypto["ciphertext"])
    plaintext = decrypt_bytes(key, nonce, ciphertext)
    return json.loads(plaintext.decode("utf-8"))

#Encrypt and persist updated vault contents
#each save generates a new random nonce and ciphertext
# then updates the vault envelope on disk
def save_with_key(key: bytes, data: Dict[str, Any]) -> None:
    vault_obj = _read_vault_obj()

    plaintext = json.dumps(data).encode("utf-8")
    nonce, ciphertext = encrypt_bytes(key, plaintext)

    vault_obj["crypto"]["nonce"] = _b64e(nonce)
    vault_obj["crypto"]["ciphertext"] = _b64e(ciphertext)
    _write_vault_obj(vault_obj)

#append new entry to the decrypted vault payload
def add_entry(data: Dict[str, Any], site: str, username: str, password: str) -> None:
    data.setdefault("entries", []).append(
        {"site": site.strip(), "username": username.strip(), "password": password}
    )

#return list of vault entries (site, username, password)
def list_entries(data: Dict[str, Any]) -> List[Dict[str, str]]:
    return data.get("entries", [])
