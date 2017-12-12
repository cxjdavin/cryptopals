'''
URL: http://cryptopals.com/sets/3/challenges/22
Title: Crack an MT19937 seed

Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

1) Wait a random number of seconds between, I don't know, 40 and 1000.
2) Seeds the RNG with the current Unix timestamp
3) Waits a random number of seconds again.
4) Returns the first 32 bit output of the RNG.

You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.
'''

from challenge_util import *

def main():
  # 1) Wait a random number of seconds between, I don't know, 40 and 1000
  time.sleep(random.randint(40,1000))

  # 2) Seeds the RNG with the current Unix timestamp
  seed = int(time.time())
  print("Seed used: {0}".format(seed))
  MT = MersenneTwister()
  MT.seed_mt(seed)

  # 3) Waits a random number of seconds again
  time.sleep(random.randint(40,1000))

  # 4) Returns the first 32 bit output of the RNG
  output = MT.extract_number()

  # Since we know the seed is unix time from past few seconds
  # Just brute force from current time backwards
  guess = -1
  for i in range(int(time.time()), -1 ,-1):
    MT_guess = MersenneTwister()
    MT_guess.seed_mt(i)
    if MT_guess.extract_number() == output:
      guess = i
      break
  print("Guessed  : {0}".format(guess))

if __name__ == "__main__":
  main()

