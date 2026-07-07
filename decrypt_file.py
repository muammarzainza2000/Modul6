"""
decrypt_file.py
===============
Script dekripsi file oleh penerima menggunakan private key-nya:
1. Dekripsi symmetric key menggunakan private key RSA
2. Dekripsi file dengan symmetric key yang sudah didekripsi

Referensi:
- Boneh, D., & Shoup, V. (2023). A Graduate Course in Applied Cryptography.
  Chapter 9: Public Key Encryption
  https://toc.cryptobook.us/
- Python cryptography - Authenticated Encryption:
  https://cryptography.io/en/latest/hazmat/primitives/aead/
"""

import os
import sys
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


def load_private_key_from_file(path: str):
    """Load private key RSA dari file PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def decrypt_file(
    receiver: str,
    enc_file_path: str,
    enc_key_path: str,
    output_dir: str = None
):
    """
    Dekripsi file oleh receiver.
    
    Langkah:
    1. Load encrypted symmetric key dari file
    2. Dekripsi symmetric key menggunakan private key receiver (RSA-OAEP)
    3. Load encrypted file
    4. Dekripsi file menggunakan symmetric key (AES-256-GCM)
       - GCM otomatis memverifikasi integritas data (authentication tag)
       - Jika data dimodifikasi, akan raise InvalidTag exception
    5. Simpan hasil dekripsi
    
    Args:
        receiver: nama penerima (untuk memuat private key-nya)
        enc_file_path: path ke file terenkripsi (.enc)
        enc_key_path: path ke encrypted symmetric key (.key.enc)
        output_dir: direktori output (default: folder receiver)
    """
    if output_dir is None:
        output_dir = f"{receiver.lower()}/received"
    os.makedirs(output_dir, exist_ok=True)

    receiver_priv_key_path = f"{receiver.lower()}/{receiver.lower()}_private_key.pem"
    receiver_priv_key = load_private_key_from_file(receiver_priv_key_path)

    print(f"\n[{receiver}] Mendekripsi file dari: {enc_file_path}")

    # === STEP 1: Dekripsi Symmetric Key ===
    with open(enc_key_path, "rb") as f:
        encrypted_symmetric_key = f.read()

    # Dekripsi dengan RSA-OAEP menggunakan private key receiver
    symmetric_key = receiver_priv_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[{receiver}] ✓ Symmetric key berhasil didekripsi ({len(symmetric_key)*8} bit)")

    # === STEP 2: Load Encrypted File ===
    with open(enc_file_path, "r") as f:
        enc_payload = json.load(f)

    nonce = base64.b64decode(enc_payload["nonce"])
    ciphertext = base64.b64decode(enc_payload["ciphertext"])
    original_filename = enc_payload["original_filename"]
    sender = enc_payload.get("sender", "Unknown")

    print(f"[{receiver}] Pengirim: {sender}")
    print(f"[{receiver}] File asli: {original_filename}")

    # === STEP 3: Dekripsi File dengan AES-256-GCM ===
    # GCM otomatis memverifikasi authentication tag
    # Jika ada yang mengubah ciphertext, decrypt() akan raise InvalidTag
    aesgcm = AESGCM(symmetric_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        print(f"[{receiver}] ✓ Integritas file VERIFIED (GCM authentication tag valid)")
    except Exception as e:
        print(f"[{receiver}] ✗ GAGAL! File mungkin sudah dimodifikasi atau corrupt!")
        print(f"[{receiver}]   Error: {e}")
        return None

    # === STEP 4: Simpan File Hasil Dekripsi ===
    output_path = f"{output_dir}/{original_filename}"
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[{receiver}] ✓ File berhasil didekripsi: {output_path}")
    print(f"[{receiver}]   Ukuran file: {len(plaintext)} byte")
    print(f"\n[{receiver}] === ISI FILE ===")
    print(plaintext.decode(errors="replace"))
    print(f"[{receiver}] ===============")

    return output_path


if __name__ == "__main__":
    print("=" * 60)
    print("  DEKRIPSI FILE - Bob menerima dari Alice")
    print("=" * 60)
    
    decrypt_file(
        receiver="Bob",
        enc_file_path="shared/secret_message.txt.enc",
        enc_key_path="shared/secret_message.txt.key.enc",
        output_dir="bob/received"
    )
