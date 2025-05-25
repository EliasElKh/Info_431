# Info_431
# Lightweight Cryptography Toolkit

This project demonstrates simplified cryptographic systems and attacks using Python. It includes:

- **S-AES (Simplified AES)** with CTR mode for encryption/decryption
- **Brute-force attacks** against S-AES and SDES ciphers using known plaintext
- **SDES (Simplified DES)** in OFB mode (targeted in brute-force attack)

---

## File Structure

| File         | Purpose                                      |
|--------------|----------------------------------------------|
| `stage_2.py` | S-AES encryption/decryption (CTR mode)       |
| `stage_3.py` | Brute-force key recovery for `stage_2.py`    |
| `stage_4.py` | Brute-force attack on SDES + OFB encrypted file |

---

## 1. `stage_2.py` – S-AES with CTR Mode

This file implements **Simplified AES** (16-bit block size and key) with **CTR (Counter) mode**. It supports encrypting and decrypting files (text or binary) using a predefined key and nonce.

### How It Works

CTR mode:
- Encrypts a counter combined with a nonce
- XORs the result with the plaintext to produce ciphertext
- Decryption works the same way as encryption

### How to Use

1. Put data in `input.txt`
2. Run:
   ```bash
   python stage_2.py
