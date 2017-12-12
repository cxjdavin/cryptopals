'''
URL: http://cryptopals.com/sets/3/challenges/23
Title: Clone an MT19937 RNG from its output

The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.

---
Stop and think for a second.

How would you modify MT19937 to make this attack hard? What would happen if you subjected each tempered output to a cryptographic hash?
---
'''

from challenge_util import *

'''
Undo tempering steps of MersenneTwister output
'''
def untemper(params, outputs):
  assert(len(outputs) == params['n'])
  n = params['n']
  w = params['w']
  l = params['l']
  t = params['t']
  c = params['c']
  s = params['s']
  b = params['b']
  u = params['u']
  d = params['d']

  state = [-1] * n
  for i in range(n):
    y = outputs[i]

    # Undo y = y ^ (y >> l), bit by bit from the left
    for j in range(w-l):
      offset = w-l-j-1
      bit = (y >> l) & (1 << offset)
      y = y ^ bit

    # Undo y = y ^ ((y << t) & c), bit by bit from the right
    for j in range(t, w+1):
      offset = j-1
      bit = (y << t) & c & (1 << offset)
      y = y ^ bit

    # Undo y = y ^ ((y << s) & b), bit by bit from the right
    for j in range(s, w+1):
      offset = j-1
      bit = (y << s) & b & (1 << offset)
      y = y ^ bit

    # Undo y = y ^ ((y >> u) & d), bit by bit from the left
    for j in range(w-u):
      offset = w-u-j-1
      bit = (y >> u) & d & (1 << offset)
      y = y ^ bit

    # Sanity check
    z = y
    z = z ^ ((z >> u) & d)
    z = z ^ ((z << s) & b)
    z = z ^ ((z << t) & c)
    z = z ^ (z >> l)
    assert(z == outputs[i])

    # Store state
    state[i] = y

  return state

'''
Splice state into a new MT19937 generator
'''
def splice(params, state):
  # Create PRNG with same parameters
  rng = MersenneTwister(w = params['w'], 
                        n = params['n'], 
                        m = params['m'], 
                        r = params['r'], 
                        a = params['a'], 
                        u = params['u'], 
                        d = params['d'], 
                        s = params['s'], 
                        b = params['b'], 
                        t = params['t'], 
                        c = params['c'], 
                        l = params['l'], 
                        f = params['f']) 

  # Modify state of PRNG based on untemper
  for i in range(params['n']):
    rng.MT[i] = state[i]

  # Update index as the PRNG has already read out n outputs
  rng.index = params['n']
  return rng

def main(N):
  # Create MT19937 PRNG and seed randomly
  MT = MersenneTwister()
  MT.seed_mt(int(time.time()))

  # Parameters are assumed to be "public", so it's okay to just extract them
  # (Not cheating)
  params = MT.params

  # Extract sufficient outputs
  outputs = []
  for i in range(params['n']):
    outputs.append(MT.extract_number())

  # Reverse outputs to obtain MT19937 internal state
  state = untemper(params, outputs)

  # Clone a copy with the appropriate state
  MT2 = splice(params, state)

  # Test that the cloned PRNG behaves the same as the original MT19937 PRNG
  print("Generate and compare the next {0} numbers from both PRNGs".format(N))
  print("          MT           MT2")
  for i in range(N):
    MT_out = MT.extract_number()
    MT2_out = MT2.extract_number()
    print("Test {0:3}: {1:11} {2:11}".format(i+1, MT_out, MT2_out))
    assert(MT_out == MT2_out)

if __name__ == "__main__":
  if len(sys.argv) >= 2 and sys.argv[1].isdigit():
    N = int(sys.argv[1])
    main(N)
  else:
    print("Usage: python3 challenge23.py <number of tests>")

