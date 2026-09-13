"""
Task 1: Modes of Operation
Implements ECB and CBC modes using AES-128 primitive (one block at a time).
Includes PKCS#7 padding and BMP encryption with header preservation.
"""
import os
import sys
from Crypto.Cipher import AES


BLOCK_SIZE = 16  # AES-128 block size in bytes


def pkcs7_pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    for byte in data[-pad_len:]:
        if byte != pad_len:
            raise ValueError("Invalid padding")
    return data[:-pad_len]


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def aes_encrypt_block(key, block):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def aes_decrypt_block(key, block):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


def ecb_encrypt(key, plaintext):
    padded = pkcs7_pad(plaintext)
    ciphertext = b''
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        ciphertext += aes_encrypt_block(key, block)
    return ciphertext


def ecb_decrypt(key, ciphertext):
    plaintext = b''
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        plaintext += aes_decrypt_block(key, block)
    return pkcs7_unpad(plaintext)


def cbc_encrypt(key, iv, plaintext):
    padded = pkcs7_pad(plaintext)
    ciphertext = b''
    prev_block = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = xor_bytes(block, prev_block)
        encrypted = aes_encrypt_block(key, xored)
        ciphertext += encrypted
        prev_block = encrypted
    return ciphertext


def cbc_decrypt(key, iv, ciphertext):
    plaintext = b''
    prev_block = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = aes_decrypt_block(key, block)
        plaintext += xor_bytes(decrypted, prev_block)
        prev_block = block
    return pkcs7_unpad(plaintext)


def encrypt_bmp(input_file, output_ecb, output_cbc, header_size=54):
    with open(input_file, 'rb') as f:
        data = f.read()

    header = data[:header_size]
    body = data[header_size:]

    key = os.urandom(16)
    iv = os.urandom(16)

    print(f"Key (hex): {key.hex()}")
    print(f"IV  (hex): {iv.hex()}")
    print(f"Input file: {input_file} ({len(data)} bytes)")
    print(f"Header size: {header_size} bytes")
    print(f"Body size: {len(body)} bytes")

    ecb_body = ecb_encrypt(key, body)
    with open(output_ecb, 'wb') as f:
        f.write(header + ecb_body)
    print(f"ECB encrypted: {output_ecb} ({len(header) + len(ecb_body)} bytes)")

    cbc_body = cbc_encrypt(key, iv, body)
    with open(output_cbc, 'wb') as f:
        f.write(header + cbc_body)
    print(f"CBC encrypted: {output_cbc} ({len(header) + len(cbc_body)} bytes)")

    # Verify decryption works
    ecb_decrypted = ecb_decrypt(key, ecb_body)
    cbc_decrypted = cbc_decrypt(key, iv, cbc_body)
    assert ecb_decrypted == body, "ECB decryption mismatch!"
    assert cbc_decrypted == body, "CBC decryption mismatch!"
    print("Decryption verification: PASSED")


if __name__ == '__main__':
    input_file = sys.argv[1] if len(sys.argv) > 1 else 'sample.bmp'
    header_size = int(sys.argv[2]) if len(sys.argv) > 2 else 54
    encrypt_bmp(input_file, 'ecb_encrypted.bmp', 'cbc_encrypted.bmp', header_size)
