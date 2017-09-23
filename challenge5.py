'''
URL: http://cryptopals.com/sets/1/challenges/5
Title: Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
'''

import codecs

def repeated_xor(key, x):
  xored = bytearray()
  for i in range(len(x)):
    xored.append(x[i] ^ key[i % len(key)])
  return bytes(xored)

def main():
  key = b'ICE'
  PT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
  PT_bytes = codecs.encode(PT)

  CT_bytes = repeated_xor(key, PT_bytes)
  CT_hex = codecs.encode(CT_bytes, "hex")
  print("CT hex: {0}".format(CT_hex))
  print()

  target_str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
  target_str_bytes = codecs.encode(target_str)
  assert(CT_hex == target_str_bytes)

if __name__ == "__main__":
  main()
