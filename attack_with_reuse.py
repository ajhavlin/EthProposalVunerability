import os
import random
import string
import time
from binascii import hexlify
from hashlib import blake2s

class LamportSigner:
    def __init__(self):
        self.private_key, self.public_key = self._generate_keys()

    def _generate_keys(self):
        private_key = [os.urandom(32) for _ in range(2)]  # Only 2 keys: one for 0 and one for 1
        public_key = [blake2s(k).digest() for k in private_key]
        return private_key, public_key

    def sign_bit(self, bit, block):
        block_hash = blake2s(block.encode()).digest()
        index = (block_hash[bit // 8] >> (bit % 8)) & 1
        return self.private_key[index]

def generate_valid_block(chars=string.ascii_letters + string.digits):
    length = random.randint(1, 2**6)
    valid_block = ''.join(random.choice(chars) for _ in range(length))
    return valid_block

start_time = time.time()

# The malicious block
block = "This is a malicious block do not sign!"
hash_func = blake2s()
hash_func.update(block.encode())
malicious_hash = hash_func.digest()

# Create 256 versions of valid blocks each matching the malicious block's hash at a bit
blocks = [None] * 256
signatures = [None] * 256
signers = [LamportSigner() for _ in range(256)]  # Create 256 signers
total_blocks_generated = 0

# Iterate over each bit until we have a valid block for each
while None in blocks:
    total_blocks_generated += 1

    # Generate a valid block
    valid_block = generate_valid_block()

    # Hash the valid block
    hash_func = blake2s()
    hash_func.update(valid_block.encode())
    valid_block_hash = hash_func.digest()

    # Check which bits match with the malicious block's hash and have not been assigned yet
    matching_bits = [(valid_block_hash[i // 8] >> (i % 8)) & 1 == (malicious_hash[i // 8] >> (i % 8)) & 1 for i in range(256)]
    unassigned_bits = [blocks[i] is None for i in range(256)]
    to_assign = [i for i, (match, unassigned) in enumerate(zip(matching_bits, unassigned_bits)) if match and unassigned]

    # If the block matches any unassigned bits, use it for those signers
    for i in to_assign:
        blocks[i] = valid_block
        signatures[i] = signers[i].sign_bit(i, valid_block) # Use the i-th signer to sign the i-th bit

# Create the "signed" malicious block by concatenating all the signatures
signed_malicious_block = b''.join(signatures)

# "Hash" the "signed" malicious block by selecting the appropriate public keys
hashed_signed_malicious_block = [signers[i].public_key[(malicious_hash[i // 8] >> (i % 8)) & 1] for i in range(256)]

end_time = time.time()


# Verify the signatures by comparing the "hashed" signed block with the public keys
for i in range(256):
    if hashed_signed_malicious_block[i] != blake2s(signed_malicious_block[i*32:(i+1)*32]).digest():
        print("Signature verification failed at bit", i)
        break
else:
    print("All signatures verified successfully")

print("Malicious hash: ", hexlify(malicious_hash).decode())
print(f"Total blocks used in the attack: {total_blocks_generated}")
print(f"Attack took {end_time - start_time} seconds.")