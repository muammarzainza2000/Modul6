"""
user_setup.py
=============
Script untuk user (Alice/Bob) melakukan setup:
1. Generate RSA key pair sendiri
2. Minta Charlie menandatangani certificate-nya
3. Simpan semua key dan certificate

Referensi:
- Boneh, D., & Shoup, V. (2023). A Graduate Course in Applied Cryptography.
  https://toc.cryptobook.us/ (Chapter 13: Public Key Encryption)
- Python cryptography docs: https://cryptography.io/en/latest/
"""

import os
import json
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Import fungsi Charlie untuk sign certificate
sys.path.insert(0, os.path.dirname(__file__))
from charlie_setup import sign_certificate


def setup_user(username: str):
    """
    Setup lengkap untuk satu user:
    1. Generate RSA-2048 key pair
    2. Minta Charlie tanda tangani certificate
    3. Simpan semua file ke folder user
    
    Menggunakan RSA-2048 untuk user (lebih ringan dari 4096 Charlie).
    NIST SP 800-57 menyatakan RSA-2048 aman hingga tahun 2030+.
    """
    user_dir = username.lower()
    os.makedirs(user_dir, exist_ok=True)
    os.makedirs("shared", exist_ok=True)

    print(f"\n[{username}] Generating RSA-2048 key pair...")

    # === STEP 1: Generate RSA Key Pair ===
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys ke format PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Simpan private key (RAHASIA, jangan dibagikan!)
    private_key_path = f"{user_dir}/{username.lower()}_private_key.pem"
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    # Simpan public key
    public_key_path = f"{user_dir}/{username.lower()}_public_key.pem"
    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    print(f"[{username}] ✓ Private key: {private_key_path}")
    print(f"[{username}] ✓ Public key:  {public_key_path}")

    # === STEP 2: Minta Charlie Tanda Tangani Certificate ===
    print(f"\n[{username}] Meminta Charlie untuk menandatangani certificate...")
    certificate = sign_certificate(username, public_pem)

    # Simpan certificate di folder user
    cert_path = f"{user_dir}/{username.lower()}_certificate.json"
    with open(cert_path, "w") as f:
        json.dump(certificate, f, indent=2)

    # Simpan juga di shared folder agar user lain bisa akses
    shared_cert_path = f"shared/{username.lower()}_certificate.json"
    with open(shared_cert_path, "w") as f:
        json.dump(certificate, f, indent=2)

    print(f"[{username}] ✓ Certificate: {cert_path}")
    print(f"[{username}] ✓ Certificate (shared): {shared_cert_path}")

    # Tampilkan isi certificate
    print(f"\n[{username}] === ISI DIGITAL CERTIFICATE ===")
    print(f"  Owner    : {certificate['owner']}")
    print(f"  PublicKey: {certificate['public_key'][:60]}...")
    print(f"  Signature: {certificate['signature'][:60]}...")
    print(f"[{username}] ================================")

    return private_key, public_key, certificate


def load_user_private_key(username: str):
    """Load private key user dari file."""
    path = f"{username.lower()}/{username.lower()}_private_key.pem"
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_user_certificate(username: str, from_shared=False) -> dict:
    """Load certificate user dari file."""
    if from_shared:
        path = f"shared/{username.lower()}_certificate.json"
    else:
        path = f"{username.lower()}/{username.lower()}_certificate.json"
    with open(path, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    print("=" * 60)
    print("  USER SETUP - Key Generation & Certificate")
    print("=" * 60)

    # Setup Alice
    print("\n>>> SETUP ALICE <<<")
    setup_user("Alice")

    # Setup Bob
    print("\n>>> SETUP BOB <<<")
    setup_user("Bob")

    print("\n[DONE] Setup semua user selesai!")
