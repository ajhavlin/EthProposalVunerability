import os
import hashlib
import random
import string
from binascii import hexlify, unhexlify
from hashlib import blake2s

class LamportSigner:
    def __init__(self):
        self.private_key, self.public_key = self._generate_keys()

    def _generate_keys(self):
        private_key = [os.urandom(32) for _ in range(512)]  # 256 pairs of keys
        public_key = [blake2s(k).digest() for k in private_key]
        return private_key, public_key

    def sign_bit(self, bit, block):
        block_hash = blake2s(block.encode()).digest()
        if ((block_hash[bit // 8] >> (bit % 8)) & 1) == 1:
            return self.private_key[2 * bit + 1]
        else:
            return self.private_key[2 * bit]

def generate_valid_block(chars=string.ascii_letters + string.digits):
    length = random.randint(1, 2**6)
    valid_block = ''.join(random.choice(chars) for _ in range(length))
    return valid_block

# The malicious block
block = "This is a malicious block do not sign!"
hash_func = blake2s()
hash_func.update(block.encode())
malicious_hash = hash_func.digest()

# Create 256 versions of valid blocks each matching the malicious block's hash at a bit
blocks = []
signatures = []
signers = [LamportSigner() for _ in range(256)]  # Create 256 signers

for i in range(256):
    while True:
        # Generate a valid block
        valid_block = generate_valid_block()

        # Hash the valid block
        hash_func = blake2s()
        hash_func.update(valid_block.encode())
        valid_block_hash = hash_func.digest()

        # If the i-th bit matches with the malicious block's hash, add it to the list
        if (valid_block_hash[i // 8] >> (i % 8)) & 1 == (malicious_hash[i // 8] >> (i % 8)) & 1:
            blocks.append(valid_block)
            signature = signers[i].sign_bit(i, valid_block)  # Use the i-th signer to sign the i-th bit
            signatures.append(signature)
            break

# Create the "signed" malicious block by concatenating all the signatures
signed_malicious_block = b''.join(signatures)

# "Hash" the "signed" malicious block by selecting the appropriate public keys
hashed_signed_malicious_block = [signers[i].public_key[2 * i + 1] if ((malicious_hash[i // 8] >> (i % 8)) & 1) == 1 else signers[i].public_key[2 * i] for i in range(256)]

# Verify the signatures by comparing the "hashed" signed block with the public keys
for i in range(256):
    if hashed_signed_malicious_block[i] != blake2s(signed_malicious_block[i*32:(i+1)*32]).digest():
        print("Signature verification failed at bit", i)
        break
else:
    print("All signatures verified successfully")

print("Malicious hash: ", hexlify(malicious_hash).decode())
