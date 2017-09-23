'''
URL: http://cryptopals.com/sets/1/challenges/3
Title: Single-byte XOR cipher

The hex encoded string:
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

Achievement Unlocked
You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
'''

import codecs

def score_string(s, score_set):
  score = 0
  for i in range(len(s)):
    if s[i] in score_set:
      score += 1
  return score

def challenge3(CT_bytes, score_set):
  best_score = -1
  best_PT = None
  best_key = None
  for key in range(2 ** 8): # Try all single characters in a byte
    PT = bytearray()
    for i in range(len(CT_bytes)):
      PT.append(CT_bytes[i] ^ key)
    score = score_string(PT, score_set)
    if score >= best_score:
      best_score = score
      best_PT = PT
      best_key = key
  return (bytes(best_PT), best_score, best_key)


def main():
  # In ASCII
  # A-Z (65-90), a-z (97-122), space (32)
  ascii_letterspaces = set(list(range(65, 91)) + list(range(97, 123)) + [32])
  
  CT = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  CT_bytes = codecs.decode(CT, "hex")
  best_PT, best_score, best_key = challenge3(CT_bytes, ascii_letterspaces)
  print("Given CT bytes: {0}".format(CT_bytes))
  print("Decoded bytes : {0}".format(best_PT))
  print()

if __name__ == "__main__":
  main()

