"""
charlie_setup.py
================
Charlie bertindak sebagai Certificate Authority (CA).
Charlie akan:
1. Generate RSA key pair miliknya sendiri
2. Menyediakan fungsi untuk menandatangani certificate user lain

Referensi:
- NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management
  https://doi.org/10.6028/NIST.SP.800-57pt1r5
- Python cryptography docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
"""

import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

CHARLIE_DIR = "charlie"
os.makedirs(CHARLIE_DIR, exist_ok=True)


def generate_charlie_keys():
    """
    Generate RSA-4096 key pair untuk Charlie.
    Menggunakan 4096-bit karena Charlie adalah root CA.
    
    Referensi: NIST SP 800-57 merekomendasikan minimal 2048-bit untuk RSA,
    4096-bit memberikan security margin lebih besar untuk CA.
    """
    print("[Charlie] Generating RSA-4096 key pair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Nilai standar, aman secara kriptografis
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Simpan private key (JANGAN dibagikan!)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"{CHARLIE_DIR}/charlie_private_key.pem", "wb") as f:
        f.write(private_pem)

    # Simpan public key (dibagikan ke semua user - hard-coded sebagai trusted)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{CHARLIE_DIR}/charlie_public_key.pem", "wb") as f:
        f.write(public_pem)

    # Simpan juga di folder shared agar Alice & Bob bisa akses
    os.makedirs("shared", exist_ok=True)
    with open("shared/charlie_public_key.pem", "wb") as f:
        f.write(public_pem)

    print(f"[Charlie] ✓ Private key disimpan di: {CHARLIE_DIR}/charlie_private_key.pem")
    print(f"[Charlie] ✓ Public key disimpan di: {CHARLIE_DIR}/charlie_public_key.pem")
    print(f"[Charlie] ✓ Public key di-copy ke: shared/charlie_public_key.pem")
    return private_key, public_key


def load_charlie_private_key():
    """Load private key Charlie dari file."""
    with open(f"{CHARLIE_DIR}/charlie_private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def sign_certificate(username: str, user_public_key_pem: bytes) -> dict:
    """
    Charlie menandatangani digital certificate untuk user.
    
    Format certificate (sederhana sesuai instruksi):
    {
        "owner": <nama user>,
        "public_key": <public key dalam PEM format, base64-encoded>,
        "signature": <tanda tangan Charlie, base64-encoded>
    }

    Algoritma signature: RSA-PSS dengan SHA-256
    Referensi: RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2
    https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
    
    PSS (Probabilistic Signature Scheme) lebih aman daripada PKCS1v15
    karena menggunakan random salt, mencegah serangan tertentu.
    """
    charlie_private_key = load_charlie_private_key()

    # Data yang akan ditandatangani: owner + public_key
    cert_data = {
        "owner": username,
        "public_key": base64.b64encode(user_public_key_pem).decode()
    }
    cert_data_bytes = json.dumps(cert_data, sort_keys=True).encode()

    # Tanda tangan menggunakan RSA-PSS + SHA-256
    signature = charlie_private_key.sign(
        cert_data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    cert_data["signature"] = base64.b64encode(signature).decode()
    
    print(f"[Charlie] ✓ Certificate untuk '{username}' berhasil ditandatangani!")
    return cert_data


def verify_certificate(certificate: dict) -> bool:
    """
    Verifikasi bahwa certificate memang ditandatangani oleh Charlie.
    Digunakan oleh Alice dan Bob untuk validasi.
    """
    with open("shared/charlie_public_key.pem", "rb") as f:
        charlie_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    try:
        # Rekonstruksi data yang ditandatangani (tanpa signature)
        cert_data = {
            "owner": certificate["owner"],
            "public_key": certificate["public_key"]
        }
        cert_data_bytes = json.dumps(cert_data, sort_keys=True).encode()
        signature = base64.b64decode(certificate["signature"])

        charlie_public_key.verify(
            signature,
            cert_data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("  CHARLIE SETUP - Certificate Authority")
    print("=" * 60)
    generate_charlie_keys()
    print("\n[Charlie] Setup selesai! Charlie siap menandatangani certificate.")
