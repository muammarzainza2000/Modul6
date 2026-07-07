"""
key_exchange.py
===============
Proses pertukaran public key dan validasi digital certificate.

Alice dan Bob saling bertukar public key + certificate,
lalu masing-masing memverifikasi bahwa:
1. Certificate memang ditandatangani Charlie (terpercaya)
2. Public key di certificate cocok dengan yang dikirim

Referensi:
- Stallings, W. (2017). Cryptography and Network Security (7th ed.). Pearson.
  Chapter 14: Key Management and Distribution
- RFC 5280: Internet X.509 Public Key Infrastructure Certificate
  https://datatracker.ietf.org/doc/html/rfc5280
"""

import json
import base64
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from charlie_setup import verify_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def extract_public_key_from_cert(certificate: dict):
    """
    Ekstrak public key dari certificate.
    Public key disimpan dalam format PEM yang di-base64-encode.
    """
    public_key_pem = base64.b64decode(certificate["public_key"])
    return serialization.load_pem_public_key(public_key_pem, backend=default_backend())


def validate_key_and_certificate(certificate: dict, sender_name: str) -> bool:
    """
    Validasi certificate yang diterima dari sender:
    1. Verifikasi signature Charlie valid
    2. Verifikasi nama owner sesuai

    Ini mencegah man-in-the-middle attack di mana
    seseorang mengirim certificate orang lain.
    
    Referensi: Kaufman, C. et al. (2002). Network Security: Private 
    Communication in a Public World (2nd ed.). Prentice Hall.
    """
    print(f"  [VALIDASI] Memverifikasi certificate dari '{sender_name}'...")

    # Check 1: Apakah certificate ditandatangani Charlie?
    if not verify_certificate(certificate):
        print(f"  [VALIDASI] ✗ GAGAL! Signature Charlie tidak valid!")
        return False
    print(f"  [VALIDASI] ✓ Signature Charlie: VALID")

    # Check 2: Apakah owner certificate sesuai?
    if certificate["owner"] != sender_name:
        print(f"  [VALIDASI] ✗ GAGAL! Owner '{certificate['owner']}' ≠ '{sender_name}'")
        return False
    print(f"  [VALIDASI] ✓ Owner certificate: VALID ('{sender_name}')")

    return True


def perform_key_exchange():
    """
    Simulasi proses pertukaran kunci antara Alice dan Bob.
    
    Dalam implementasi nyata, ini terjadi melalui jaringan.
    Di sini kita simulasikan dengan membaca dari folder shared.
    """
    print("=" * 60)
    print("  KEY EXCHANGE - Alice ↔ Bob")
    print("=" * 60)

    # Load certificate dari shared folder (simulasi pengiriman via jaringan)
    with open("shared/alice_certificate.json") as f:
        alice_cert = json.load(f)
    with open("shared/bob_certificate.json") as f:
        bob_cert = json.load(f)

    # --- BOB MEMVERIFIKASI CERTIFICATE ALICE ---
    print("\n[Bob] Menerima certificate dari Alice...")
    bob_validates_alice = validate_key_and_certificate(alice_cert, "Alice")

    if bob_validates_alice:
        alice_pub_key = extract_public_key_from_cert(alice_cert)
        # Simpan public key Alice untuk digunakan Bob nanti
        with open("bob/alice_public_key_received.pem", "wb") as f:
            f.write(alice_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[Bob] ✓ Public key Alice tersimpan dan siap digunakan!")
    else:
        print("[Bob] ✗ Certificate Alice DITOLAK! Proses dihentikan.")
        return False

    # --- ALICE MEMVERIFIKASI CERTIFICATE BOB ---
    print("\n[Alice] Menerima certificate dari Bob...")
    alice_validates_bob = validate_key_and_certificate(bob_cert, "Bob")

    if alice_validates_bob:
        bob_pub_key = extract_public_key_from_cert(bob_cert)
        # Simpan public key Bob untuk digunakan Alice nanti
        with open("alice/bob_public_key_received.pem", "wb") as f:
            f.write(bob_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[Alice] ✓ Public key Bob tersimpan dan siap digunakan!")
    else:
        print("[Alice] ✗ Certificate Bob DITOLAK! Proses dihentikan.")
        return False

    print("\n[KEY EXCHANGE] ✓ Pertukaran kunci berhasil! Alice dan Bob siap berkomunikasi.")
    return True


if __name__ == "__main__":
    success = perform_key_exchange()
    if not success:
        print("\n[ERROR] Key exchange gagal!")
        sys.exit(1)
