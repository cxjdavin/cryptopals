'''
URL: http://cryptopals.com/sets/1/challenges/6
Title: Break repeating-key XOR

It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file (challenge6.txt) here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
  this is a test
and
  wokka wokka!!!
is 37. Make sure your code agrees before you proceed.

3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.

4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.

5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.

7. Solve each block as if it was single-character XOR. You already have code to do this.

8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.
'''

import codecs
import sys
from challenge3 import challenge3
from challenge5 import repeated_xor

# Count number of 1's in (x XOR y)
# x and y are in bytes
def hamming(x, y):
  assert(len(x) == len(y))
  count = 0
  for i in range(len(x)):
    xored = x[i] ^ y[i]
    xored_bin = bin(xored).strip("0b")
    for j in range(len(xored_bin)):
      if xored_bin[j] == "1":
        count += 1
  return count

def test_hamming():
  x1 = codecs.encode("this is a test")
  x2 = codecs.encode("wokka wokka!!!")
  assert(hamming(x1, x2) == 37)

def read_challenge(filename, encoding):
  CT = ""
  with open(filename, 'r') as fin:
    for line in fin:
      CT += line
  if encoding == "ascii":
    return codecs.encode(CT)
  else:
    return codecs.decode(codecs.encode(CT), encoding)

# Rank key sizes k in [lb, lb+1, ..., ub] in ascending "normalized edit distance"
# "normalized edit distance" for a given k =
#   sum over hamming(A,B)/k for every pairwise bytes A and B (in the first "groupsize" bytes)
def rank_keylengths(CT_bytes, lb, ub, groupsize):
  key_lengths = []
  for k in range(lb, ub+1):
    groups = []
    for i in range(groupsize):
      groups.append(CT_bytes[i*k : (i+1)*k])
    score = 0
    for i in range(groupsize):
      for j in range(i+1, groupsize):
        score += hamming(groups[i], groups[j])
    score = score / k
    key_lengths.append((score, k))
  key_lengths = sorted(key_lengths)
  return key_lengths

# ned = "normalized edit distance"
# search from most promising key lengths, up to bestKL lengths
# for each key length, search for best byte key
def test_keylengths(CT_bytes, keylength_ranking, score_set, bestKL):
  output = []
  for kl in range(min(len(keylength_ranking), bestKL)):
    ned, keylength = keylength_ranking[kl]

    # Chunk up CT in keylength
    transposed_chunks = []
    for i in range(keylength):
      transposed_chunks.append([])
    for i in range(len(CT_bytes)):
      transposed_chunks[i % keylength].append(CT_bytes[i])

    # For each column, find the best byte key
    best_key = bytearray()
    for i in range(keylength):
      PT_bytes, score, key = challenge3(transposed_chunks[i], score_set)
      best_key.append(key)

    # Decode according to best key
    PT_bytes = repeated_xor(best_key, CT_bytes)
    output.append((keylength, best_key, PT_bytes))
  return output

def main(argv):
  # In ASCII
  # A-Z (65-90), a-z (97-122), space (32)
  ascii_letterspaces = set(list(range(65, 91)) + list(range(97, 123)) + [32])

  # Parse parameters, or use default
  lowerbound = 2
  upperbound = 40
  groupsize  = 4
  if len(argv) >= 2:
    bestKL = int(argv[1])
  else:
    bestKL = 1 # Just output top guess

  test_hamming()
  CT_bytes = read_challenge("challenge6.txt", "base64")
  keylength_ranking = rank_keylengths(CT_bytes, lowerbound, upperbound, groupsize)
  guesses = test_keylengths(CT_bytes, keylength_ranking, ascii_letterspaces, bestKL)

  for keylength, best_key, PT_bytes in guesses:
    print("Best key of length {0}: {1}".format(keylength, best_key))
    print("Decoded:\n{0}".format(PT_bytes))
    print()

if __name__ == "__main__":
  print("Usage: python3 challenge6.py <Optional: bestKL. Default = 1>")
  main(sys.argv)

