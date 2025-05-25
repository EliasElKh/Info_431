P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
P8 = [5, 2, 6, 3, 7, 4, 9, 8]
IP = [1, 5, 2, 0, 3, 7, 4, 6]
IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]
EP = [3, 0, 1, 2, 1, 2, 3, 0]
P4 = [1, 3, 2, 0]

S0 = [
    [[0, 1], [0, 0], [1, 1], [1, 0]],
    [[1, 1], [1, 0], [0, 1], [0, 0]],
    [[0, 0], [1, 0], [0, 1], [1, 1]],
    [[1, 1], [0, 1], [1, 1], [0, 0]]
]

S1 = [
    [[0, 0], [0, 1], [1, 0], [1, 1]],
    [[1, 0], [0, 0], [0, 1], [1, 1]],
    [[1, 1], [0, 0], [0, 1], [0, 0]],
    [[1, 0], [0, 1], [0, 0], [1, 1]]
]

def permute(bits, p):
    return [bits[i] for i in p]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def key_generation(key):
    key = permute(key, P10)
    left, right = key[:5], key[5:]
    left, right = left_shift(left, 1), left_shift(right, 1)
    K1 = permute(left + right, P8)
    left, right = left_shift(left, 2), left_shift(right, 2)
    K2 = permute(left + right, P8)
    return K1, K2

def sbox_lookup(bits, sbox):
    row = (bits[0] << 1) + bits[3]
    col = (bits[1] << 1) + bits[2]
    return sbox[row][col]

def fk(bits, key):
    left, right = bits[:4], bits[4:]
    expanded = permute(right, EP)
    temp = xor(expanded, key)
    s0_out = sbox_lookup(temp[:4], S0)
    s1_out = sbox_lookup(temp[4:], S1)
    combined = permute(s0_out + s1_out, P4)
    return xor(left, combined) + right

def sdes_encrypt(plain_bits, K1, K2):
    bits = permute(plain_bits, IP)
    bits = fk(bits, K1)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K2)
    return permute(bits, IP_inv)

def sdes_decrypt(cipher_bits, K1, K2):
    bits = permute(cipher_bits, IP)
    bits = fk(bits, K2)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, K1)
    return permute(bits, IP_inv)


def ofb_encrypt(plaintext_bits, iv, K1, K2):
    output = []
    feedback = iv[:]
    for block in plaintext_bits:
        feedback = sdes_encrypt(feedback, K1, K2)
        cipher_block = [b ^ f for b, f in zip(block, feedback)]
        output.append(cipher_block)
    return output

def ofb_decrypt(ciphertext_bits, iv, K1, K2):
    return ofb_encrypt(ciphertext_bits, iv, K1, K2)


def brute_force(ciphertext_bits, iv, known_plaintext_blocks):
    for k in range(1024):
        key_bits = [int(b) for b in format(k, '010b')]
        K1, K2 = key_generation(key_bits)
        decrypted = ofb_decrypt(ciphertext_bits, iv, K1, K2)

        match = all(decrypted[i] == known_plaintext_blocks[i] for i in range(len(known_plaintext_blocks)))
        if match:
            print(f"Key found: {key_bits}")
            return key_bits
    print("Key not found.")
    return None

def read_cipher_from_bin(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    bitstring = ''.join(format(byte, '08b') for byte in data)
    bits = [int(b) for b in bitstring]
    blocks = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return blocks

def string_to_bits(s):
    return [[int(b) for b in format(ord(c), '08b')] for c in s]

if __name__ == "__main__":
    plaintext = "Cha"  # known part
    iv = [0, 1, 0, 1, 1, 0, 0, 1]
    read_cipher = read_cipher_from_bin("ciphertext.bin")
    plain_bits = string_to_bits(plaintext)

    # Brute force using known plaintext
    known_blocks = plain_bits[:2]
    print("\nBrute-forcing from binary file...")
    key_bits = brute_force(read_cipher, iv, known_blocks)

    if key_bits:
        K1, K2 = key_generation(key_bits)
        decrypted_bits = ofb_decrypt(read_cipher, iv, K1, K2)

        # Convert decrypted bits to characters
        decrypted_text = ''.join(chr(int(''.join(map(str, block)), 2)) for block in decrypted_bits)
        print(f"\nDecrypted Text: {decrypted_text}")
