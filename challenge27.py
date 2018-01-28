'''
URL: http://cryptopals.com/sets/4/challenges/27
Title: Recover the key from CBC with IV=Key
Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:
AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

Modify the message (you are now the attacker):
C_1, C_2, C_3 -> C_1, 0, C_1

Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:
P'_1 XOR P'_3
'''

from challenge_util import *

def random_URL(n):
  output = bytearray(b"http://")
  for i in range(n-7):
    output.append(random.randint(0, 128))
  return bytes(output)

def check_for_high_byte_value(byte_string):
  for x in byte_string:
    if x > 128:
      return True
  return False

def main(L):
  # (HIDDEN) Setup
  random_AES_key = random_bytes(AES_block_size)
  random_CBC_IV  = random_AES_key
  assert(random_AES_key == random_CBC_IV)

  # Use a length at least 3x the AES block size
  length = min(L, AES_block_size * 3)
  PT_bytes = random_URL(length)
  CT_bytes = CBC_encrypt(PT_bytes, random_AES_key, random_CBC_IV)

  CT_1 = get_block(CT_bytes, 0)
  zeroes = b"\x00" * AES_block_size
  CT_rest = CT_bytes[3 * AES_block_size : ] # To account for pkcs7 paddings

  modified_CT_bytes = CT_1 + bytes(zeroes) + CT_1 + CT_rest
  decrypted_bytes = CBC_decrypt(modified_CT_bytes, random_AES_key, random_CBC_IV)

  sound_alert = check_for_high_byte_value(decrypted_bytes)
  recovered_key = fixed_xor(get_block(decrypted_bytes, 0), get_block(decrypted_bytes, 2))

  print("Original AES key: {0}".format(random_AES_key))
  print("Recovered key   : {0}".format(recovered_key))
  assert(recovered_key == random_AES_key)
  print("Sound alert: {0}".format(sound_alert))

if __name__ == "__main__":
  if len(sys.argv) >= 2 and sys.argv[1].isdigit():
    L = int(sys.argv[1])
    main(L)
  else:
    print("Usage: python3 challenge27.py <length of random URL (will be rounded up to 3 blocks)>")
