'''
URL: http://cryptopals.com/sets/2/challenges/9
Title: Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
'''

import codecs
import sys
from Crypto.Cipher import AES

# x is in bytes
def pkcs7(x, block_size):
  pad_length = block_size - (len(x) % block_size)
  padded_x = bytearray(x)
  for i in range(pad_length):
    padded_x.append(pad_length)
  return bytes(padded_x)

def main(block_size):
  padded = pkcs7(codecs.encode("YELLOW SUBMARINE"), block_size)
  assert(len(padded) % block_size == 0)
  num_chunks = len(padded) // block_size
  chunks = [padded[i*block_size : (i+1)*block_size] for i in range(num_chunks)]
  print("Pad length: {0:2} -> {1}".format(block_size, padded))
  print("In blocks : {0}".format(chunks))

if __name__ == "__main__":
  if len(sys.argv) >= 2 and sys.argv[1].isdigit():
    main(int(sys.argv[1]))
  else:
    print("Usage: python3 challenge9.py <integer block size>")

