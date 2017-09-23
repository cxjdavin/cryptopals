'''
URL: http://cryptopals.com/sets/1/challenges/8
Title: Detect AES in ECB mode

In this file (challenge8.txt) are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
'''

import codecs
from Crypto.Cipher import AES

def read_challenge(filename, encoding, multiline = False):
  if multiline:
    CT = []
    with open(filename, 'r') as fin:
      for line in fin:
        CT.append(line[:-1]) # Ignore trailing "\n"    
  else:
    CT = ""
    with open(filename, 'r') as fin:
      for line in fin:
        CT += line
  if encoding == "ascii":
    if multiline:
      return [codecs.encode(ct) for ct in CT]
    else:
      return codecs.encode(CT)
  else:
    if multiline:
      return [codecs.decode(codecs.encode(ct), encoding) for ct in CT]
    else:
      return codecs.decode(codecs.encode(CT), encoding)

def get_block(x, idx, block_size):
  assert(len(x) >= idx * block_size)
  return x[idx * block_size : (idx+1) * block_size]

def detect_AES_ECB(CT_bytes):
  AES_block_size = 16
  output = []
  for line_idx in range(len(CT_bytes)):
    ctb = CT_bytes[line_idx]
    assert(len(ctb) % AES_block_size == 0)
    num_bytes = len(ctb) // 16

    # Check for repeating ciphertext bytes
    same = []
    for i in range(num_bytes):
      for j in range(i+1, num_bytes):
        x = get_block(ctb, i, AES_block_size)
        y = get_block(ctb, j, AES_block_size)
        if x == y:
          same.append((i,j))

    # Record lines that have repeated bytes
    # Note: line_idx is 0-based
    if len(same) != 0:
      output.append((line_idx, same))
  return output

def main():
  CT_bytes = read_challenge("challenge8.txt", "hex", multiline = True)
  lines_with_repeated_bytes = detect_AES_ECB(CT_bytes)
  
  # Note: line_idx is 0-based
  AES_block_size = 16
  for line_idx, same in lines_with_repeated_bytes:
    print("Line {0} has byte collisions at {1}".format(line_idx + 1, same))
    for i in range(len(CT_bytes[line_idx]) // AES_block_size):
      block_i = get_block(CT_bytes[line_idx], i, AES_block_size)
      print("Block {0}: {1}".format(i, codecs.encode(block_i, "hex")))
  print()

if __name__ == "__main__":
  main()

