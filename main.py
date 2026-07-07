"""
main.py
=======
Script utama yang menjalankan seluruh protokol enkripsi end-to-end.
Urutan eksekusi:
  1. Charlie setup (CA)
  2. Alice & Bob setup (key gen + certificate)
  3. Key exchange + validasi
  4. Alice enkripsi file → Bob
  5. Bob dekripsi file

Jalankan: python main.py
"""

import os, sys
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from charlie_setup import generate_charlie_keys
from user_setup import setup_user
from key_exchange import perform_key_exchange
from encrypt_file import encrypt_file
from decrypt_file import decrypt_file

DIVIDER = "=" * 60

def main():
    print(DIVIDER)
    print("  SECURE FILE EXCHANGE PROTOCOL")
    print("  Alice ↔ Bob (trusted by Charlie)")
    print(DIVIDER)

    # --- FASE 1: SETUP ---
    print("\n\n>>> FASE 1: SETUP <<<")
    print(DIVIDER)

    print("\n[1/3] Charlie setup sebagai Certificate Authority...")
    generate_charlie_keys()

    print("\n[2/3] Alice setup: key generation + request certificate...")
    setup_user("Alice")

    print("\n[3/3] Bob setup: key generation + request certificate...")
    setup_user("Bob")

    # --- FASE 2: KEY EXCHANGE ---
    print("\n\n>>> FASE 2: KEY EXCHANGE & VALIDASI <<<")
    print(DIVIDER)
    success = perform_key_exchange()
    if not success:
        print("\n[ABORTED] Key exchange gagal. Protocol dihentikan.")
        sys.exit(1)

    # --- FASE 3: ENKRIPSI ---
    print("\n\n>>> FASE 3: ENKRIPSI FILE (Alice → Bob) <<<")
    print(DIVIDER)

    # Buat file contoh
    os.makedirs("alice", exist_ok=True)
    test_file = "alice/secret_message.txt"
    with open(test_file, "w") as f:
        f.write("Halo Bob! Ini pesan rahasia dari Alice.\n")
        f.write("Jangan sampai ada yang tahu ya!\n")
        f.write("Kunci brankas: SuperSecretPassword123\n")

    enc_file, enc_key = encrypt_file(
        sender="Alice",
        receiver="Bob",
        file_to_encrypt=test_file,
        output_dir="shared"
    )

    # --- FASE 4: DEKRIPSI ---
    print("\n\n>>> FASE 4: DEKRIPSI FILE (Bob) <<<")
    print(DIVIDER)
    decrypt_file(
        receiver="Bob",
        enc_file_path=enc_file,
        enc_key_path=enc_key,
        output_dir="bob/received"
    )

    print("\n" + DIVIDER)
    print("  PROTOCOL SELESAI! Semua fase berhasil.")
    print(DIVIDER)

if __name__ == "__main__":
    main()
