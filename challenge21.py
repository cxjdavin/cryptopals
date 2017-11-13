'''
URL: http://cryptopals.com/sets/3/challenges/21
Title: Implement the MT19937 Mersenne Twister RNG

You can get the pseudocode for this from Wikipedia.

If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
'''

from challenge_util import *

# Reference: https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode
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

def main(seed, N):
  MT = MersenneTwister()
  MT.seed_mt(seed)
  for i in range(N):
    x = MT.extract_number()
    print(x)

if __name__ == "__main__":
  if len(sys.argv) >= 3 and sys.argv[1].isdigit() and sys.argv[2].isdigit():
    seed = int(sys.argv[1])
    N = int(sys.argv[2])
    main(seed, N)
  else:
    print("Usage: python3 challenge21.py <seed> <number of consecutive random numbers>")

