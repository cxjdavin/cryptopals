'''
URL: http://cryptopals.com/sets/1/challenges/4
Title: Detect single-character XOR

One of the 60-character strings in this file (challenge4.txt) has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
'''

import codecs
from challenge3 import challenge3

def challenge4(filename, score_set):
  CT = []
  with open(filename, 'r') as fin:
    for line in fin:
      CT.append(line[:-1]) # Ignore trailing "\n"
  print("{0} contains {1} candidate ciphertexts".format(filename, len(CT)))

  best_score = -1
  best_PT = None
  best_line_idx = None
  for i in range(len(CT)):
    CT_bytes = codecs.decode(CT[i], "hex")
    PT_bytes, score, key = challenge3(CT_bytes, score_set)
    if score >= best_score:
      best_score = score
      best_PT = PT_bytes
      best_line_idx = i
  # Note: best_line_idx is 0 based
  return (best_line_idx + 1, best_score, CT[best_line_idx], best_PT)

def main():
  # In ASCII
  # A-Z (65-90), a-z (97-122), space (32)
  ascii_letterspaces = set(list(range(65, 91)) + list(range(97, 123)) + [32])
  
  line_idx, line_score, line, PT_bytes = challenge4("challenge4.txt", ascii_letterspaces)
  print("Line {0} with score of {1} is most likely candidate".format(line_idx, line_score))
  print("CT hex       : {0}".format(line))
  print("Decoded bytes: {0}".format(PT_bytes))
  print()

if __name__ == "__main__":
  main()

