'''
URL: http://cryptopals.com/sets/3/challenges/17
Title: The CBC padding oracle
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.

---
What you're doing here.

This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.
---

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.
'''

from challenge_util import *

class Oracle:
  def __init__(self):
    secrets = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
               "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
               "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
               "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
               "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
               "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
               "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
               "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
               "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
               "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
    self.secret = codecs.encode(random.choice(secrets))
    self.AES_key = random_bytes(AES_block_size)
    self.IV = random_bytes(AES_block_size)
    print("Chosen secret:\n{0}".format(self.secret))
    print("Padded secret:\n{0}".format(pkcs7(self.secret)))

  def function1(self):
    return self.IV, CBC_encrypt(self.secret, self.AES_key, self.IV)

  def function2(self, IV, CT_bytes):
    PT_bytes = CBC_decrypt(CT_bytes, self.AES_key, IV)
    padding = int(PT_bytes[-1])
    if padding == 0:
      return False
    else:
      for i in range(padding):
        if PT_bytes[-(i+1)] != padding:
          return False
      return True

'''
Perform padding attack by guessing bytes from the back
'''
def padding_attack(oracle, IV, CT_bytes):
  guess = bytearray()
  for i in range(len(CT_bytes) // AES_block_size):
    block_idx = len(CT_bytes) // AES_block_size - 1 - i
    target_block = get_block(CT_bytes, block_idx)
    if block_idx == 0:
      prev_block = IV
    else:
      prev_block = get_block(CT_bytes, block_idx - 1)
    CT_fragment = prev_block + target_block

    guess_block = bytearray(AES_block_size)
    pad_len = 1
    while pad_len <= AES_block_size:
      modification = bytearray(2 * AES_block_size)
      for j in range(1, pad_len + 1):
        modification[-AES_block_size-j] = guess_block[-j] ^ pad_len
      if oracle.function2(IV, fixed_xor(CT_fragment, modification)):
        pad_len += 1
      else:
        if guess_block[-pad_len] < 255:
          guess_block[-pad_len] += 1
        else:
          # Backtrack
          guess_block[-pad_len] = 0
          pad_len -= 1
          guess_block[-pad_len] += 1
    guess = guess_block + guess
  return bytes(guess)

def main():
  oracle = Oracle()
  IV, CT_bytes = oracle.function1()
  guess = padding_attack(oracle, IV, CT_bytes)
  print("Guess:\n{0}".format(guess))
  print()

if __name__ == "__main__":
  main()

