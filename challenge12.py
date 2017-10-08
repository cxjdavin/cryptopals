'''
URL: http://cryptopals.com/sets/2/challenges/12
Title: Byte-at-a-time ECB decryption (Simple)

Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.

2. Detect that the function is using ECB. You already know, but do this step anyways.

3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.

4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.

6. Repeat for the next byte.

Congratulations.
This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
'''

from challenge_util import *

def encryption_oracle(PT_bytes, AES_key):
  append = codecs.decode(codecs.encode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"), "base64")
  CT_bytes = ECB_encrypt(PT_bytes + append, AES_key)
  return bytes(CT_bytes)

def main():
  # Step 0: Fix unknown random AES key
  random_AES_key = random_bytes(AES_block_size)
  
  # Step 1: Discover block size of cipher
  block_size_unknown = True
  PT_size = 1
  CT_sizes = []
  while len(CT_sizes) < 2:
    PT_bytes = codecs.encode("A" * PT_size)
    CT_bytes = encryption_oracle(PT_bytes, random_AES_key)
    if len(CT_sizes) == 0 or len(CT_bytes) != CT_sizes[-1]:
      CT_sizes.append(len(CT_bytes))
    PT_size += 1
  block_size = CT_sizes[-1] - CT_sizes[-2]
  unknown_byte_size = len(CT_bytes) - PT_size - block_size
  print("Encryption oracle block size: {0}".format(block_size))
  print("Number of unknown bytes to solve for: {0}".format(unknown_byte_size))
  
  # Step 2: Detect that it is using ECB
  PT_bytes = codecs.encode("A" * block_size * 10)
  CT_bytes = encryption_oracle(PT_bytes, random_AES_key)
  print("Is ECB: {0}".format(detect_ECB(CT_bytes)))
  
  # Step 3: Craft PT that is one byte short, so that first block "eats" into appended unknown text. Recover the first unknown byte
  # Step 4: Repeat until all bytes recovered
  solved = bytearray()
  while len(solved) < unknown_byte_size:
    offset = block_size - (len(solved) % block_size) - 1
    PT_bytes = bytearray(codecs.encode("A" * offset))
    assert((len(PT_bytes) + len(solved) + 1) % block_size == 0)
  
    block_idx = (len(PT_bytes) + len(solved) + 1) // block_size - 1
    CT_bytes = encryption_oracle(PT_bytes, random_AES_key)
    observation = get_block(CT_bytes, block_idx)
  
    # Brute force unknown last byte
    for i in range(256):
      to_try = PT_bytes + solved + bytes([i])
      outcome = get_block(encryption_oracle(to_try, random_AES_key), block_idx)
      if outcome == observation:
        solved += bytes([i])
        break
  
  # Print the decoded bytes!
  print("Decoded bytes:\n{0}".format(bytes(solved)))
  print()

if __name__ == "__main__":
  main()

