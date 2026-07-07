"""
encrypt_file.py
===============
Script enkripsi file menggunakan hybrid encryption:
1. Generate symmetric key (AES-256) secara random
2. Enkripsi file dengan AES-256-GCM
3. Enkripsi symmetric key dengan RSA-OAEP (public key penerima)
4. Output: file terenkripsi + encrypted symmetric key

Mengapa Hybrid Encryption?
- RSA lambat untuk data besar → gunakan untuk enkripsi kunci saja
- AES cepat dan efisien → gunakan untuk enkripsi data aktual
- Ini adalah pendekatan standar dalam protokol seperti TLS/SSL

Referensi:
- Boneh, D., & Shoup, V. (2023). A Graduate Course in Applied Cryptography.
  Chapter 11: Authenticated Encryption
  https://toc.cryptobook.us/
- NIST SP 800-38D: GCM Mode for Symmetric Key Block Cipher Algorithms
  https://doi.org/10.6028/NIST.SP.800-38D
- RFC 8017, Section 7.1: RSA-OAEP Encryption Scheme
  https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
"""

import os
import sys
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


def load_public_key_from_file(path: str):
    """Load public key RSA dari file PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def encrypt_file(
    sender: str,
    receiver: str,
    file_to_encrypt: str,
    output_dir: str = "shared"
):
    """
    Enkripsi file dari sender ke receiver.
    
    Langkah:
    1. Generate AES-256 symmetric key secara random (os.urandom = CSPRNG)
    2. Enkripsi file dengan AES-256-GCM
       - GCM memberikan Authenticated Encryption (confidentiality + integrity)
       - Nonce (12 byte) harus unik setiap enkripsi, jangan pernah reuse!
    3. Enkripsi symmetric key dengan RSA-OAEP menggunakan public key receiver
       - OAEP lebih aman dari PKCS1v15 karena probabilistik
    4. Simpan output:
       - <filename>.enc       : file terenkripsi
       - <filename>.key.enc   : symmetric key yang sudah dienkripsi
    
    Args:
        sender: nama pengirim (untuk logging)
        receiver: nama penerima (untuk memuat public key-nya)
        file_to_encrypt: path file yang akan dienkripsi
        output_dir: direktori untuk menyimpan output
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Load public key receiver
    receiver_pub_key_path = f"{sender.lower()}/{receiver.lower()}_public_key_received.pem"
    receiver_pub_key = load_public_key_from_file(receiver_pub_key_path)
    
    print(f"\n[{sender}] Mengenkripsi file: '{file_to_encrypt}'")
    print(f"[{sender}] Penerima: {receiver}")

    # === STEP 1: Generate Symmetric Key AES-256 ===
    # os.urandom menggunakan CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
    # Ini AMAN, berbeda dengan random.random() yang tidak boleh dipakai untuk kriptografi
    symmetric_key = os.urandom(32)  # 256 bit = 32 byte
    print(f"[{sender}] ✓ AES-256 symmetric key generated ({len(symmetric_key)*8} bit)")

    # === STEP 2: Enkripsi File dengan AES-256-GCM ===
    # Nonce: 12 byte, harus unik per enkripsi
    # GCM menghasilkan ciphertext + authentication tag (16 byte) sekaligus
    nonce = os.urandom(12)  # 96 bit nonce, standar untuk GCM
    aesgcm = AESGCM(symmetric_key)

    with open(file_to_encrypt, "rb") as f:
        plaintext = f.read()

    # encrypt() mengembalikan ciphertext + tag (sudah digabung otomatis)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Simpan encrypted file (nonce + ciphertext disatukan)
    filename = os.path.basename(file_to_encrypt)
    enc_file_path = f"{output_dir}/{filename}.enc"
    
    # Format: nonce (12 byte) || ciphertext+tag
    enc_payload = {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "original_filename": filename,
        "sender": sender,
        "receiver": receiver
    }
    with open(enc_file_path, "w") as f:
        json.dump(enc_payload, f, indent=2)
    
    print(f"[{sender}] ✓ File terenkripsi: {enc_file_path}")
    print(f"[{sender}]   Ukuran asli   : {len(plaintext)} byte")
    print(f"[{sender}]   Ukuran cipher : {len(ciphertext)} byte")

    # === STEP 3: Enkripsi Symmetric Key dengan RSA-OAEP ===
    # RSA-OAEP dengan SHA-256 sebagai hash function
    # OAEP = Optimal Asymmetric Encryption Padding (probabilistik, lebih aman dari PKCS1v15)
    encrypted_symmetric_key = receiver_pub_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Simpan encrypted symmetric key
    enc_key_path = f"{output_dir}/{filename}.key.enc"
    with open(enc_key_path, "wb") as f:
        f.write(encrypted_symmetric_key)
    
    print(f"[{sender}] ✓ Encrypted symmetric key: {enc_key_path}")
    print(f"\n[{sender}] Pengiriman ke {receiver} siap!")
    print(f"[{sender}]   File 1: {enc_file_path}  (berisi ciphertext)")
    print(f"[{sender}]   File 2: {enc_key_path} (berisi encrypted symmetric key)")

    return enc_file_path, enc_key_path


if __name__ == "__main__":
    # Contoh: Alice mengenkripsi file dan mengirim ke Bob
    import os

    # Buat file contoh untuk dienkripsi
    test_file = "alice/secret_message.txt"
    with open(test_file, "w") as f:
        f.write("Halo Bob! Ini pesan rahasia dari Alice.\n")
        f.write("Jangan sampai ada yang tahu ya! 🔐\n")
        f.write("Kunci WiFi rumahku: SuperSecretPassword123\n")

    print("=" * 60)
    print("  ENKRIPSI FILE - Alice → Bob")
    print("=" * 60)
    
    encrypt_file(
        sender="Alice",
        receiver="Bob",
        file_to_encrypt=test_file,
        output_dir="shared"
    )
