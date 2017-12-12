'''
URL: http://cryptopals.com/sets/4/challenges/25
Title: Break "random access read/write" AES CTR
Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.

---
Food for thought.

A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.
---
'''

from challenge_util import *

'''
Replace offset chunk by encrypted newtext
Note: Extends ciphertext if newtext longer than replacement
'''
def edit(CT_bytes, key_bytes, nonce_bytes, offset, newtext):
  PT_bytes = CTR_decrypt(CT_bytes, key_bytes, nonce_bytes)
  PT_prepend = PT_bytes[:offset]
  PT_append = PT_bytes[offset + len(newtext):]
  PT_bytes = PT_prepend + newtext + PT_append

  ctr = 0
  keystream = bytearray()
  while len(keystream) < len(PT_bytes):
    msg = nonce_bytes + ctr.to_bytes(8, "little")
    keystream += lib_ECB_encrypt(msg, key_bytes)
    ctr += 1
  CT_bytes = fixed_xor(PT_bytes, keystream[:len(PT_bytes)])
  return bytes(CT_bytes)

def main():
  file_bytes = read_challenge("challenge25.txt", "base64")
  PT_bytes = ECB_decrypt(file_bytes, b"YELLOW SUBMARINE")

  unknown_CTR_key = random_bytes(16)
  unknown_nonce = random_bytes(8)
  CT_bytes = CTR_encrypt(PT_bytes, unknown_CTR_key, unknown_nonce)

  # Idea: CTR_encrypt(zeroes) = keystream
  # Run edit(..., zeroes) to extract keystream, then xor with CT to recover PT
  mod_bytes = CT_bytes
  zeroes = b"\x00" * len(CT_bytes)
  mod_bytes = edit(mod_bytes, unknown_CTR_key, unknown_nonce, 0, zeroes)
  recovered_bytes = fixed_xor(CT_bytes, mod_bytes[:len(CT_bytes)])

  print("Recovered:")
  print(recovered_bytes)
  print()

if __name__ == "__main__":
  main()

