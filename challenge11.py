'''
URL: http://cryptopals.com/sets/2/challenges/11
Title: An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
'''

from challenge_util import *

def encryption_oracle(PT_bytes):
  random_AES_key = random_bytes(AES_block_size)
  prepend = random_bytes(random.randint(5,10))
  append = random_bytes(random.randint(5,10))
  PT_bytes = pkcs7(prepend + PT_bytes + append)

  mode = ""
  if random.random() < 0.5:
    # Run ECB
    mode = "ECB"
    CT_bytes = ECB_encrypt(PT_bytes, random_AES_key)
  else:
    # Run CBC
    mode = "CBC"
    random_IV = random_bytes(AES_block_size)
    CT_bytes = CBC_encrypt(PT_bytes, random_AES_key, random_IV)
  return [mode, bytes(CT_bytes)]

def detect(num_tests):
  num_correct = 0
  for i in range(num_tests):
    PT_bytes = codecs.encode("A"*100)
    mode, CT_bytes = encryption_oracle(PT_bytes)
    repeated_chunks = find_repeated_chunks(CT_bytes)

    guess = None
    if len(repeated_chunks) == 0:
      guess = "CBC"
    else:
      guess = "ECB"
    if mode == guess:
      num_correct += 1
    print("Test {0:3} || Guess: {1} | Ans: {2}".format(i+1, guess, mode))
  print("Score: {0}/{1}".format(num_correct, num_tests))
  print()

def main(num_tests):
  detect(num_tests)

if __name__ == "__main__":
  if len(sys.argv) >= 2 and sys.argv[1].isdigit():
    main(int(sys.argv[1]))
  else:
    print("Usage: python3 challenge11.py <integer number of tests>")

