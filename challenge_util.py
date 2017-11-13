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
lib_ECB: From library
ECB: ECB mode with padding handling
CBC: CBC mode written from scratch using _ECB as black box (See challenge10)
'''
def lib_ECB_decrypt(CT_bytes, key_bytes):
  cipher = AES.new(key_bytes, AES.MODE_ECB)
  PT_bytes = cipher.decrypt(CT_bytes)
  return PT_bytes

def lib_ECB_encrypt(PT_bytes, key_bytes):
  cipher = AES.new(key_bytes, AES.MODE_ECB)
  CT_bytes = cipher.encrypt(PT_bytes)
  return bytes(CT_bytes)

# Remove padding
def ECB_decrypt(CT_bytes, key_bytes):
  PT_bytes = lib_ECB_decrypt(CT_bytes, key_bytes)
  padded = int(PT_bytes[-1])
  return bytes(PT_bytes[:-padded])

# pkcs7
def ECB_encrypt(PT_bytes, key_bytes):
  PT_bytes = pkcs7(PT_bytes)
  assert(len(PT_bytes) % AES_block_size == 0)
  return lib_ECB_encrypt(PT_bytes, key_bytes)

def CBC_decrypt(CT_bytes, key_bytes, IV):
  assert(len(CT_bytes) % AES_block_size == 0)
  PT_bytes = bytearray()
  CT_block = IV
  for i in range(len(CT_bytes) // AES_block_size):
    PT_bytes += fixed_xor(CT_block, lib_ECB_decrypt(get_block(CT_bytes, i), key_bytes))
    CT_block = get_block(CT_bytes, i)
  return bytes(PT_bytes)

def CBC_encrypt(PT_bytes, key_bytes, IV):
  PT_bytes = pkcs7(PT_bytes)
  assert(len(PT_bytes) % AES_block_size == 0)
  CT_bytes = bytearray()
  CT_block = IV
  for i in range(len(PT_bytes) // AES_block_size):
    CT_block = lib_ECB_encrypt(fixed_xor(CT_block, get_block(PT_bytes, i)), key_bytes)
    CT_bytes += CT_block
  return bytes(CT_bytes)

def CTR_encrypt(PT_bytes, key_bytes, nonce):
  ctr = 0
  keystream = bytearray()
  while len(keystream) < len(PT_bytes):
    msg = nonce.to_bytes(8, "little") + ctr.to_bytes(8, "little")
    keystream += lib_ECB_encrypt(msg, key_bytes)
    ctr += 1
  CT_bytes = fixed_xor(PT_bytes, keystream[:len(PT_bytes)])
  return bytes(CT_bytes)

def CTR_decrypt(CT_bytes, key_bytes, nonce):
  return CTR_encrypt(CT_bytes, key_bytes, nonce)

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

'''
Returns random bytes of length [lb, ub] 
'''
def random_bytes_range(lb, ub):
  return random_bytes(random.randint(lb, ub+1))

'''
MersenneTwister implementation (See challenge21)
Reference: https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode
'''
class MersenneTwister:
  def __init__(self,
               w = 32,
               n = 624,
               m = 397,
               r = 31,
               a = 0x9908B0DF,
               u = 11,
               d = 0xFFFFFFFF,
               s = 7,
               b = 0x9D2C5680,
               t = 15,
               c = 0xEFC60000,
               l = 18,
               f = 1812433253):
    self.params = dict()
    self.params['w'] = w
    self.params['n'] = n
    self.params['m'] = m
    self.params['r'] = r
    self.params['a'] = a
    self.params['u'] = u
    self.params['d'] = d
    self.params['s'] = s
    self.params['b'] = b
    self.params['t'] = t
    self.params['c'] = c
    self.params['l'] = l
    self.params['f'] = f

    self.MT = [0] * n
    self.index = n+1
    self.lower_mask = (1 << r) - 1 # That is, the binary number of r 1's
    self.upper_mask = (1 << w) - 1 - self.lower_mask

  # Initialize the generator from a seed
  def seed_mt(self, seed):
    n = self.params['n']
    w = self.params['w']
    f = self.params['f']

    self.index = n
    self.MT[0] = seed
    for i in range(1, n):
      val = f * (self.MT[i-1] ^ (self.MT[i-1] >> (w-2))) + i
      self.MT[i] = val & ((1 << w) - 1)

  # Extract a tempered value based on MT[index]
  # calling twist every n numbers
  def extract_number(self):
    w = self.params['w']
    n = self.params['n']
    u = self.params['u']
    d = self.params['d']
    s = self.params['s']
    b = self.params['b']
    t = self.params['t']
    c = self.params['c']
    l = self.params['l']

    if self.index >= n:
      if self.index > n:
        print("Generator was never seeded")
        # Alternatively, seed with constant value; 5489 is used in reference C code
      self.twist()

    y = self.MT[self.index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    self.index = self.index + 1
    return y & ((1 << w) - 1)

  # Generate the next n values from the series x_i
  def twist(self):
    n = self.params['n']
    m = self.params['m']
    a = self.params['a']

    for i in range(n):
      x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % n] & self.lower_mask)
      xA = (x >> 1)
      if x % 2 != 0: # lowest bit of x is 1
        xA = xA ^ a
      self.MT[i] = self.MT[(i+m) % n] ^ xA
    self.index = 0

