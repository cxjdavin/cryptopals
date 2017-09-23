'''
URL: http://cryptopals.com/sets/1/challenges/2
Title: Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:
1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:
686974207468652062756c6c277320657965
... should produce:
746865206b696420646f6e277420706c6179
'''

import codecs

def fixed_xor(b1, b2):
  assert(len(b1) == len(b2))
  xored = bytearray()
  for i in range(len(b1)):
    xored.append(b1[i] ^ b2[i])
  return bytes(xored)

def main():
  x = "1c0111001f010100061a024b53535009181c"
  y = "686974207468652062756c6c277320657965"
  
  x_bytes = codecs.decode(x, "hex")
  y_bytes = codecs.decode(y, "hex")
  xored = fixed_xor(x_bytes, y_bytes)
  
  print("x bytes   : {0}".format(x_bytes))
  print("y bytes   : {0}".format(y_bytes))
  print("xored     : {0}".format(xored))
  print("xored hex : {0}".format(codecs.encode(xored, "hex")))
  print()

if __name__ == "__main__":
  main()

