"""
Task 2: Limits of Confidentiality
Implements submit() and verify() oracle functions, then performs a CBC bit-flipping
attack to inject ";admin=true;" into the decrypted plaintext.
"""
import os
from task1_modes import cbc_encrypt, cbc_decrypt, BLOCK_SIZE

# Generate a random key and IV once for the entire program
KEY = os.urandom(16)
IV = os.urandom(16)

PREFIX = "userid=456;userdata="
SUFFIX = ";session-id=31337"


def submit(user_input):
    escaped = user_input.replace(';', '%3B').replace('=', '%3D')
    plaintext = PREFIX + escaped + SUFFIX
    plaintext_bytes = plaintext.encode('ascii')
    ciphertext = cbc_encrypt(KEY, IV, plaintext_bytes)
    return ciphertext


def verify(ciphertext):
    plaintext_bytes = cbc_decrypt(KEY, IV, ciphertext)
    plaintext = plaintext_bytes.decode('ascii', errors='replace')
    print(f"  Decrypted: {plaintext}")
    return ";admin=true;" in plaintext


def cbc_bitflip_attack():
    """
    The prefix "userid=456;userdata=" is 20 bytes, so it occupies:
      - Block 0 (bytes 0-15): "userid=456;userd"
      - Block 1 (bytes 16-19): "ata="

    User input starts at byte 20 (block index 1, offset 4).
    We want ";admin=true;" in the decrypted plaintext.

    Strategy: provide a user input that puts known characters at positions
    we can flip. We'll target block 2 (bytes 32-47) in the plaintext.
    To control block 2's plaintext, we flip bits in ciphertext block 1.

    The user input starts at offset 20. We need 12 bytes to fill the rest
    of block 1 (bytes 20-31), then our target text starts at byte 32.

    We'll provide "XadminXtrueX" as the payload starting at byte 32,
    and flip X -> ; or = by modifying ciphertext block 1.
    """
    # Pad to align: 12 bytes fill block 1 (bytes 20-31), then target at block 2
    filler = "A" * 12  # fills bytes 20-31 (rest of block 1)
    target = "XadminXtrueX"  # will become ";admin=true;"
    user_input = filler + target

    print(f"User input: '{user_input}'")
    ciphertext = submit(user_input)

    print("\nBefore attack:")
    result = verify(ciphertext)
    print(f"  verify() returned: {result}")

    # Modify ciphertext block 1 to flip characters in plaintext block 2
    # Plaintext block 2 = AES_decrypt(ciphertext_block_2) XOR ciphertext_block_1
    # To change plaintext byte at position p in block 2:
    #   flip ciphertext_block_1[p] ^= original_char ^ desired_char
    ct = bytearray(ciphertext)

    # Target positions within block 2 (byte 32-47 of plaintext):
    # Position 0: 'X' -> ';'  (byte 32 of plaintext = index 0 in block 2)
    # Position 6: 'X' -> '='  (byte 38)
    # Position 11: 'X' -> ';' (byte 43)
    block1_start = BLOCK_SIZE  # ciphertext block 1 starts at byte 16

    ct[block1_start + 0] ^= ord('X') ^ ord(';')
    ct[block1_start + 6] ^= ord('X') ^ ord('=')
    ct[block1_start + 11] ^= ord('X') ^ ord(';')

    modified_ciphertext = bytes(ct)

    print("\nAfter attack (CBC bit-flipping):")
    result = verify(modified_ciphertext)
    print(f"  verify() returned: {result}")

    return result


if __name__ == '__main__':
    print("=" * 60)
    print("Task 2: CBC Bit-Flipping Attack")
    print("=" * 60)

    print("\n--- Normal submit/verify ---")
    ct = submit("hello world")
    print(f"verify('hello world'): {verify(ct)}")

    print("\n--- Attempting to inject admin directly ---")
    ct = submit(";admin=true;")
    print(f"verify(';admin=true;'): {verify(ct)}")

    print("\n--- CBC Bit-Flipping Attack ---")
    success = cbc_bitflip_attack()
    print(f"\nAttack {'succeeded' if success else 'failed'}!")
