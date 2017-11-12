'''
URL: http://cryptopals.com/sets/3/challenges/20
Title: Break fixed-nonce CTR statistically

In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
'''

from challenge_util import *

def produce_CT():
  all_PT_bytes = read_challenge("challenge20.txt", "base64", True)
  random_AES_key = random_bytes(AES_block_size)
  fixed_nonce = 0
  all_CT_bytes = [CTR_encrypt(PT, random_AES_key, fixed_nonce) for PT in all_PT_bytes]
  return all_PT_bytes, all_CT_bytes

'''
Modified from challenge3
'''
def guess_xor_byte(CT_bytes, score_set):
  best_score = -1
  best_xor = None
  for b in range(2 ** 8): # Try all single characters in a byte
    PT = bytearray()
    for i in range(len(CT_bytes)):
      PT.append(CT_bytes[i] ^ b)
    score = score_string(PT, score_set)
    if score >= best_score:
      best_score = score
      best_xor = b
  return best_xor

'''
See challenge6 on breaking repeating-key XOR
Here, we treat key length as the minimum length of all CT
'''
def modified_repeating_XOR_attack(all_CT_bytes):
  xor_len = min([len(x) for x in all_CT_bytes])
  transposed_chunks = []
  for i in range(xor_len):
    transposed = []
    for j in range(len(all_CT_bytes)):
      transposed.append(all_CT_bytes[j][i])
    transposed_chunks.append(transposed)
  
  # For each column, find most likely xor stream from CTR output
  xor_stream = bytearray()
  for i in range(xor_len):
    xor_byte = guess_xor_byte(transposed_chunks[i], ascii_letterspaces)
    xor_stream.append(xor_byte)

  # Decode according to most likely xor stream
  decoded_bytes = []
  for i in range(len(all_CT_bytes)):
    decoded = fixed_xor(xor_stream, all_CT_bytes[i][:xor_len])
    for j in range(len(all_CT_bytes[i]) - xor_len):
      decoded += b'?'
    decoded_bytes.append(decoded)

  return decoded_bytes

def main():
  all_PT_bytes, all_CT_bytes = produce_CT()
  decoded_bytes = modified_repeating_XOR_attack(all_CT_bytes)

  # Compare
  for i in range(len(all_PT_bytes)):
    print("Original: {0}".format(all_PT_bytes[i]))
    print("Decoded : {0}".format(decoded_bytes[i]))

if __name__ == "__main__":
  main()

