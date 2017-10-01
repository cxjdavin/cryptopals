'''
Frequently used things in challenges
Will be added over time as I progress through the challenges
'''

import codecs
import random
import sys
from Crypto.Cipher import AES

#
# Constants
#
ascii_letterspaces = set(list(range(65, 91)) + list(range(97, 123)) + [32])
AES_block_size = 16

#
# Functions
#
'''
Given 2 same length bytes, return their XOR
'''
def fixed_xor(b1, b2):
  assert(len(b1) == len(b2))
  xored = bytearray()
  for i in range(len(b1)):
    xored.append(b1[i] ^ b2[i])
  return bytes(xored)

'''
Returns number of characters in s that matches a given scoring set
'''
def score_string(s, score_set):
  score = 0
  for i in range(len(s)):
    if s[i] in score_set:
      score += 1
  return score

'''
Returns file content in bytes
If multiline = True, then return an array of bytes with each line as an element
'''
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

'''
Return the idx-th block of bytes x
Assume block_size = AES_block_size unless otherwise stated
'''
def get_block(x, idx, block_size = AES_block_size):
  assert(len(x) >= idx * block_size)
  return x[idx * block_size : (idx+1) * block_size]

'''
Given bytes x, return PKCS7 padded version of it
Assume block_size = AES_block_size unless otherwise stated
'''
def pkcs7(x, block_size = AES_block_size):
  pad_length = block_size - (len(x) % block_size)
  padded_x = bytearray(x)
  for i in range(pad_length):
    padded_x.append(pad_length)
  return bytes(padded_x)

'''
AES encryption/decryption via ECB and CBC modes
ECB: From library
CBC: Written from scratch on using ECB as black box (See challenge10)
'''
def ECB_decrypt(CT_bytes, key_bytes):
  cipher = AES.new(key_bytes, AES.MODE_ECB)
  PT_bytes = cipher.decrypt(CT_bytes)

  # Remove padding
  padded = int(PT_bytes[-1])
  return bytes(PT_bytes[:-padded])

def ECB_encrypt(PT_bytes, key_bytes):
  PT_bytes = pkcs7(PT_bytes)
  assert(len(PT_bytes) % AES_block_size == 0)
  cipher = AES.new(key_bytes, AES.MODE_ECB)
  CT_bytes = cipher.encrypt(PT_bytes)
  return bytes(CT_bytes)

def CBC_decrypt(CT_bytes, key_bytes, IV):
  assert(len(CT_bytes) % AES_block_size == 0)
  PT_bytes = bytearray()
  CT_block = IV
  for i in range(len(CT_bytes) // AES_block_size):
    PT_bytes += fixed_xor(CT_block, ECB_decrypt(get_block(CT_bytes, i), key_bytes))
    CT_block = get_block(CT_bytes, i)
  return bytes(PT_bytes)

def CBC_encrypt(PT_bytes, key_bytes, IV):
  assert(len(PT_bytes) % AES_block_size == 0)
  CT_bytes = bytearray()
  CT_block = IV
  for i in range(len(PT_bytes) // AES_block_size):
    CT_block = ECB_encrypt(fixed_xor(CT_block, get_block(PT_bytes, i)), key_bytes)
    CT_bytes += CT_block
  return bytes(CT_bytes)

'''
Given bytes x, return array of (i,j) where x[i] = x[j]
'''
def find_repeated_chunks(x):
  assert(len(x) % 16 == 0)
  num_bytes = len(x) // 16
  repeated = []
  for i in range(num_bytes):
    for j in range(i+1, num_bytes):
      xi = get_block(x, i)
      xj = get_block(x, j)
      if xi == xj:
        repeated.append((i,j))
  return repeated

'''
Detect ECB mode by checking if there are repeated chunks
Note: False positives likely for very long messages
      False negatives likely for short messages
'''
def detect_ECB(x):
  return len(find_repeated_chunks(x)) != 0

'''
Returns n random bytes
'''
def random_bytes(n):
  output = bytearray()
  for i in range(n):
    output.append(random.randint(0, 255))
  return bytes(output)

