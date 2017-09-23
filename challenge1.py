'''
URL: http://cryptopals.com/sets/1/challenges/1
Title: Convert hex to base64

The string:
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

Cryptopals Rule
Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
'''

import codecs

def change_byte_encoding(x, encoding1, encoding2):
  return codecs.encode(codecs.decode(x, encoding1), encoding2)

def main():
  x = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
  y = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
  
  print("Input         : {0}".format(x))
  print("Desired output: {0}".format(y))
  print("Decoded input : {0}".format(codecs.decode(x, "hex")))
  print("Output        : {0}".format(change_byte_encoding(x, "hex", "base64")))
  print()

if __name__ == "__main__":
  main()

