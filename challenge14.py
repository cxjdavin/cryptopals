'''
URL: http://cryptopals.com/sets/2/challenges/14
Title: Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
'''

from challenge_util import *

class Oracle:
  def __init__(self, random_prefix, target_bytes, random_AES_key):
    self.prefix = random_prefix
    self.target = target_bytes
    self.key = random_AES_key

  def encrypt(self, PT_bytes):
    PT_bytes = self.prefix + PT_bytes + self.target
    CT_bytes = ECB_encrypt(PT_bytes, self.key)
    return bytes(CT_bytes)

def form_buffer(buffer_len):
  return codecs.encode("A" * buffer_len)

'''
Let buffer be "AA..A"
We encrypt: <prefix><buffer><target>

Increase buffer_len from 0, ...
  -> If new block created, derive combined_len = prefix_len + target_len
Compute first index with different blocks with buffer_len 0 and 1
Increase buffer_len from 2, ...
  -> If indexed block stays the same, we have padded beyond required padding for prefix_len
  -> Compute prefix_len                        
Compute target_len = combined_len - prefix_len
'''
def step1(oracle):
  combined_len = None
  prefix_len = None
  target_len = None
  init_CT = oracle.encrypt(form_buffer(0))

  # Find combined length
  for i in range(AES_block_size):
    CT_bytes = oracle.encrypt(form_buffer(i))
    if len(CT_bytes) != len(init_CT):
      combined_len = len(init_CT) - i
      break

  # Find changing block
  prev_CT = init_CT
  next_CT = oracle.encrypt(form_buffer(1))
  for i in range(len(prev_CT) // 16):
    if get_block(prev_CT, i) != get_block(next_CT, i):
      change_idx = i
      break

  # Find prefix_len
  prev_CT = next_CT
  for i in range(2, AES_block_size + 2):
    next_CT = oracle.encrypt(form_buffer(i))
    if get_block(prev_CT, change_idx) == get_block(next_CT, change_idx):
      prefix_len = AES_block_size * (change_idx + 1) - (i - 1)
      break
    else:
      prev_CT = next_CT

  target_len = combined_len - prefix_len
  return prefix_len, target_len

def step3(oracle, prefix_len, target_len, block_offset):
  solved = bytearray()
  prepend_len = AES_block_size - (prefix_len % AES_block_size)
  while len(solved) < target_len:
    offset_len = AES_block_size - (len(solved) % AES_block_size) - 1
    PT_bytes = form_buffer(prepend_len + offset_len)
    CT_bytes = oracle.encrypt(PT_bytes)

    # Brute force unknown last byte
    block_idx = block_offset + (offset_len + len(solved)) // AES_block_size
    observation = get_block(CT_bytes, block_idx)  
    for i in range(256):
      to_try = PT_bytes + solved + bytes([i])
      outcome = get_block(oracle.encrypt(to_try), block_idx)
      if outcome == observation:
        solved += bytes([i])
        break
  return bytes(solved)

def main(argv):
  # (HIDDEN) Step 0: Setup
  if (len(argv) >= 5
      and argv[1].isdigit()
      and argv[2].isdigit()
      and argv[3].isdigit()
      and argv[4].isdigit()):
    prefix_lb = int(argv[1])
    prefix_ub = int(argv[2])
    target_lb = int(argv[3])
    target_ub = int(argv[4])
  else:
    prefix_lb = 50
    prefix_ub = 100
    target_lb = 50
    target_ub = 100

  print("Setup...")
  print("random_prefix  as random k bytes, where k \in [{0}, {1}]".format(prefix_lb, prefix_ub))
  print("target_bytes   as random k bytes, where k \in [{0}, {1}]".format(target_lb, target_ub))
  print("random_AES_key as random {0} bytes".format(AES_block_size))
  random_prefix  = random_bytes_range(prefix_lb, prefix_ub)
  target_bytes   = random_bytes_range(target_lb, target_ub)
  random_AES_key = random_bytes(AES_block_size)
  oracle = Oracle(random_prefix, target_bytes, random_AES_key)
  print("Setup done\n")

  # Step 1: Find lengths of random_prefix and target_bytes
  prefix_len, target_len = step1(oracle)

  # SANITY CHECK
  assert(prefix_len == len(random_prefix))
  assert(target_len == len(target_bytes))
  print("Prefix length: {0}".format(prefix_len))
  print("Target length: {0}".format(target_len))

  # Step 3: Reuse challenge12's attack with block offset to account for random_prefix
  block_offset = prefix_len // AES_block_size + 1
  print("Block offset : {0}".format(block_offset))
  solved = step3(oracle, prefix_len, target_len, block_offset)
  
  # SANITY CHECK 
  assert(solved == target_bytes)
  print("Target bytes: {0}".format(target_bytes))
  print("Solved bytes: {0}".format(solved))
  print()

if __name__ == "__main__":
  print("Usage: python3 challenge14.py prefix_lb prefix_ub target_lb target_ub")
  print("Let k1 = random integer from [prefix_lb, prefix_ub], 1 <= prefix_lb <= prefix_ub")
  print("    k2 = random integer from [target_lb, target_ub], 1 <= target_lb <= target_ub")
  print("Then, random_prefix = random k1 bytes")
  print("      target_bytes  = random k2 bytes")
  print("Default: prefix_lb = target_lb = 50, prefix_ub = target_ub = 100")
  print()
  main(sys.argv)

