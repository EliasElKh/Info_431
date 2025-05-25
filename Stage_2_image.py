# Full S-AES implementation with CTR mode in Python

SBOX = [0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7]

INV_SBOX = [10, 5, 9, 11,
            1, 7, 8, 15,
            6, 0, 2, 3,
            12, 4, 13, 14]

# Irreducible polynomial for GF(2^4)
GF_MOD = 0b10011  # x^4 + x + 1

def gf4_mul(a, b):
    """Multiply two elements (4 bits) in GF(2^4) modulo x^4 + x + 1."""
    product = 0
    for i in range(4):
        if (b & 1) != 0:
            product ^= a
        carry = a & 0x8
        a <<= 1
        if carry != 0:
            a ^= GF_MOD
        b >>= 1
    return product & 0xF  # Keep only 4 bits

def sub_nib(byte):
    """Substitute each nibble (4 bits) of an 8-bit byte using SBOX."""
    return (SBOX[byte >> 4] << 4) | SBOX[byte & 0x0F]

def inv_sub_nib(byte):
    """Inverse substitute each nibble of an 8-bit byte."""
    return (INV_SBOX[byte >> 4] << 4) | INV_SBOX[byte & 0x0F]

def sub_word(word):
    """Substitute each nibble of a 16-bit word (4 nibbles)."""
    return (SBOX[(word >> 12) & 0xF] << 12) | (SBOX[(word >> 8) & 0xF] << 8) | (SBOX[(word >> 4) & 0xF] << 4) | SBOX[word & 0xF]

def rot_word(word):
    """Rotate 16-bit word left by 4 bits (1 nibble)."""
    return ((word << 4) & 0xFFFF) | (word >> 12)

def shift_rows(s):
    """ShiftRows operation on 16-bit state: swap nibble 2 and nibble 3."""
    # State nibbles: s0 s1 s2 s3 (each 4 bits)
    s0 = (s >> 12) & 0xF
    s1 = (s >> 8) & 0xF
    s2 = (s >> 4) & 0xF
    s3 = s & 0xF
    # Shift row 1: swap s2 and s3
    return (s0 << 12) | (s1 << 8) | (s3 << 4) | s2

def inv_shift_rows(s):
    """Inverse ShiftRows: swap nibble 2 and nibble 3 (same as shift_rows)."""
    return shift_rows(s)

def mix_columns(s):
    """MixColumns for S-AES: multiply matrix in GF(2^4)."""
    # Matrix multiply:
    # |1 4|
    # |4 1|
    s0 = (s >> 12) & 0xF
    s1 = (s >> 8) & 0xF
    s2 = (s >> 4) & 0xF
    s3 = s & 0xF

    r0 = gf4_mul(s0, 1) ^ gf4_mul(s2, 4)
    r1 = gf4_mul(s1, 1) ^ gf4_mul(s3, 4)
    r2 = gf4_mul(s0, 4) ^ gf4_mul(s2, 1)
    r3 = gf4_mul(s1, 4) ^ gf4_mul(s3, 1)

    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3

def inv_mix_columns(s):
    """Inverse MixColumns for S-AES."""
    # Matrix multiply by inverse matrix:
    # |9 2|
    # |2 9|
    s0 = (s >> 12) & 0xF
    s1 = (s >> 8) & 0xF
    s2 = (s >> 4) & 0xF
    s3 = s & 0xF

    r0 = gf4_mul(s0, 9) ^ gf4_mul(s2, 2)
    r1 = gf4_mul(s1, 9) ^ gf4_mul(s3, 2)
    r2 = gf4_mul(s0, 2) ^ gf4_mul(s2, 9)
    r3 = gf4_mul(s1, 2) ^ gf4_mul(s3, 9)

    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3

def add_round_key(s, k):
    """XOR state with round key."""
    return s ^ k

def key_expansion(key):
    """Expand 16-bit key into three 16-bit round keys."""
    # W0 and W1 are the original 8-bit halves of key
    W = [0]*6
    W[0] = (key >> 8) & 0xFF
    W[1] = key & 0xFF

    RCON1 = 0x80  # 1000 0000
    RCON2 = 0x30  # 0011 0000

    def sub_byte(b):
        return SBOX[b >> 4] << 4 | SBOX[b & 0x0F]

    W[2] = W[0] ^ (sub_byte(rot_nibble(W[1])) ^ RCON1)
    W[3] = W[2] ^ W[1]
    W[4] = W[2] ^ (sub_byte(rot_nibble(W[3])) ^ RCON2)
    W[5] = W[4] ^ W[3]

    round_keys = [
        (W[0] << 8) | W[1],
        (W[2] << 8) | W[3],
        (W[4] << 8) | W[5],
    ]
    return round_keys

def rot_nibble(b):
    """Rotate 8-bit nibble left by 4 bits."""
    return ((b << 4) & 0xF0) | ((b >> 4) & 0x0F)

def s_aes_encrypt(block, round_keys):
    """Encrypt one 16-bit block with S-AES."""
    state = add_round_key(block, round_keys[0])
    # Round 1
    state = sub_word(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_keys[1])
    # Round 2
    state = sub_word(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[2])
    return state

def s_aes_decrypt(block, round_keys):
    """Decrypt one 16-bit block with S-AES."""
    state = add_round_key(block, round_keys[2])
    state = inv_shift_rows(state)
    state = inv_sub_word(state)
    state = add_round_key(state, round_keys[1])
    state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_word(state)
    state = add_round_key(state, round_keys[0])
    return state

def inv_sub_word(word):
    """Inverse substitute each nibble in a 16-bit word."""
    return (INV_SBOX[(word >> 12) & 0xF] << 12) | (INV_SBOX[(word >> 8) & 0xF] << 8) | (INV_SBOX[(word >> 4) & 0xF] << 4) | INV_SBOX[word & 0xF]

def increment_counter(counter):
    return (counter + 1) & 0xFFFF

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def ctr_encrypt(plaintext_bytes, key, nonce=0):
    """Encrypt plaintext bytes using S-AES CTR mode with 16-bit key."""
    round_keys = key_expansion(key)
    ciphertext = bytearray()
    counter = 0
    for i in range(0, len(plaintext_bytes), 2):
        block = plaintext_bytes[i:i+2]
        if len(block) < 2:
            block += b'\x00'  # pad last block if needed

        # Create 16-bit counter block: nonce(8 bits) | counter(8 bits)
        ctr_block = (nonce << 8) | (counter & 0xFF)
        encrypted_ctr = s_aes_encrypt(ctr_block, round_keys)
        encrypted_ctr_bytes = encrypted_ctr.to_bytes(2, byteorder='big')
        cipher_block = xor_bytes(block, encrypted_ctr_bytes)
        ciphertext.extend(cipher_block)

        counter = increment_counter(counter)
    return bytes(ciphertext)

def ctr_decrypt(ciphertext_bytes, key, nonce=0):
    """Decrypt ciphertext bytes using S-AES CTR mode (same as encryption)."""
    return ctr_encrypt(ciphertext_bytes, key, nonce)

def test_files():
    key = 0x3A94  # Example 16-bit key

    # Test with a text file
    with open('mini1.jpg', 'rb') as f:
        plaintext = f.read()

    ciphertext = ctr_encrypt(plaintext, key)
    with open('encrypted_image.bin', 'wb') as f:
        f.write(ciphertext)

    with open('encrypted_image.bin', 'rb') as f:
        ciphertext = f.read()

    decrypted = ctr_decrypt(ciphertext, key)
    with open('decrypted_image.jpg', 'wb') as f:
        f.write(decrypted)

    # Verify files match
    assert plaintext == decrypted, "Decryption failed! Files do not match."

    print("Text file encryption/decryption successful!")

    # You can do the same with images or any other binary file by changing file names

if __name__ == '__main__':
    test_files()
