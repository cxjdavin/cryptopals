'''
URL: http://cryptopals.com/sets/2/challenges/15
Title: PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:
"ICE ICE BABY\x04\x04\x04\x04"
... has valid padding, and produces the result "ICE ICE BABY".

The string:
"ICE ICE BABY\x05\x05\x05\x05"
... does not have valid padding, nor does:
"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
'''

from challenge_util import *

def strip_padding(x_bytes):
  padding = int(x_bytes[-1])
  for i in range(padding):
    if x_bytes[-(i+1)] != padding:
      return False
  return bytes(x_bytes[:-padding])

def main():
  x1 = codecs.encode("ICE ICE BABY\x04\x04\x04\x04")
  x2 = codecs.encode("ICE ICE BABY\x05\x05\x05\x05")
  x3 = codecs.encode("ICE ICE BABY\x01\x02\x03\x04")

  print("{0} -> {1}".format(x1, strip_padding(x1)))
  print("{0} -> {1}".format(x2, strip_padding(x2)))
  print("{0} -> {1}".format(x3, strip_padding(x3)))
  print()

if __name__ == "__main__":
  main()
