'''
URL: http://cryptopals.com/sets/2/challenges/10
Title: Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here (challenge10.txt) is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?
'''

from challenge_util import *

def ECB_decrypt(CT_bytes, key_bytes):
  cipher = AES.new(key_bytes, AES.MODE_ECB)
  PT_bytes = cipher.decrypt(CT_bytes)
  return bytes(PT_bytes)

def ECB_encrypt(PT_bytes, key_bytes):
  cipher = AES.new(key_bytes, AES.MODE_ECB)
  CT_bytes = cipher.encrypt(PT_bytes)
  return bytes(CT_bytes)

def CBC_decrypt(CT_bytes, key_bytes, IV):
  assert(len(CT_bytes) % AES_block_size == 0)
  PT_bytes = bytearray()
  CT_block = IV
  for i in range(len(CT_bytes) // AES_block_size):
    PT_bytes += fixed_xor(CT_block, ECB_decrypt(get_block(CT_bytes, i), key_bytes))
    CT_block = get_block(CT_bytes, i)
  return bytes(PT_bytes)

def CBC_encrypt(PT_bytes, key_bytes, IV):
  assert(len(PT_bytes) % AES_block_size == 0)
  CT_bytes = bytearray()
  CT_block = IV
  for i in range(len(PT_bytes) // AES_block_size):
    CT_block = ECB_encrypt(fixed_xor(CT_block, get_block(PT_bytes, i)), key_bytes)
    CT_bytes += CT_block
  return bytes(CT_bytes)

def main():
  IV = codecs.encode("\x00" * AES_block_size)
  CT_bytes = read_challenge("challenge10.txt", "base64")
  key_bytes = codecs.encode("YELLOW SUBMARINE")
  PT_bytes = CBC_decrypt(CT_bytes, key_bytes, IV)
  re_encrypted = CBC_encrypt(PT_bytes, key_bytes, IV)
  assert(CT_bytes == re_encrypted)
  print("Decoded bytes:\n{0}".format(PT_bytes))
  print()

if __name__ == "__main__":
  main()

