'''
URL: http://cryptopals.com/sets/3/challenges/24
Title: Create the MT19937 stream cipher and break it

You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
'''

from challenge_util import *

class MT19937_Stream:
  def __init__(self, seed):
    self.seed = seed
    self.MT = MersenneTwister()
    self.setup()

  def setup(self):
    self.MT.seed_mt(self.seed)

  def get_xor_byte(self):
    return self.MT.extract_number() & ((1 << 8) - 1)

  def encrypt(self, PT_bytes):
    self.setup()
    xor_stream = bytearray()
    for i in range(len(PT_bytes)):
      xor_stream.append(self.get_xor_byte())
    return fixed_xor(PT_bytes, xor_stream)

  # Since we're using the PRNG like a one-time pad, decrypt() = encrypt()
  def decrypt(self, CT_bytes):
    return self.encrypt(CT_bytes)

'''
16 bits is very small, we can just brute force
'''
def recover_MTS_16bit_seed(PT_bytes, CT_bytes):
  for s in range(2 ** 16):
    MTS = MT19937_Stream(s)
    attempt = MTS.encrypt(PT_bytes)
    if attempt == CT_bytes:
      return s

def generate_password_reset_token(token_len):
  use_MTS = random.random() < 0.5
  token = []
  if use_MTS:
    seed = int(time.time()) & ((1 << 16) - 1)
    MTS = MT19937_Stream(seed)
    for i in range(token_len):
      token.append(MTS.get_xor_byte())
  else:
    for i in range(token_len):
      token.append(random.randint(0,255))
  return use_MTS, token

'''
16 bits is very small, we can just brute force
'''
def guess_if_MTS(token, token_len):
  for s in range(2 ** 16):
    MTS = MT19937_Stream(s)
    attempt = []
    for i in range(token_len):
      x = MTS.get_xor_byte()
      if x != token[i]:
        break
      else:
        attempt.append(x)
    if attempt == token:
      return True
  return False

def main(N, token_len):
  # Test MTS on random 16-bit seed
  seed = int(time.time()) & ((1 << 16) - 1)
  MTS = MT19937_Stream(seed)
  PT_bytes = random_bytes(random.randint(50, 100)) + codecs.encode("AAAAAAAAAAAAAA")
  CT_bytes = MTS.encrypt(PT_bytes)
  decoded = MTS.decrypt(CT_bytes)
  assert(decoded == PT_bytes)
  '''
  # Recovering 16 bit seed from PT-CT pair
  print("Seed used   : {0}".format(seed))
  guess_seed = recover_MTS_16bit_seed(PT_bytes, CT_bytes)
  print("Guessed seed: {0}".format(guess_seed))
  '''
  score = 0
  for i in range(N):
    use_MTS, token = generate_password_reset_token(token_len)
    guess = guess_if_MTS(token, token_len)
    print("Test {0:3}: {1} {2}".format(i+1, use_MTS, guess))
    if guess == use_MTS:
      score += 1
  print("Total score: {0} / {1}".format(score, N))

if __name__ == "__main__":
  if len(sys.argv) >= 2 and sys.argv[1].isdigit() and sys.argv[2].isdigit():
    N = int(sys.argv[1])
    token_len = int(sys.argv[2])
    main(N, token_len)
  else:
    print("Usage: python3 challenge23.py <number of tests> <reset token length>")

