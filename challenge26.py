'''
URL: http://cryptopals.com/sets/4/challenges/26
Title: CTR bitflipping
There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier (challenge16.py) to use CTR mode instead of CBC mode. Inject an "admin=true" token.
'''

from challenge_util import *

'''
Takes in a string PT
Convert ; and = to ';' and '='
Apply prepend and append
Perform CTR encrypt
'''
def function1(PT, AES_key, CTR_nonce):
  # Quote out ";" and "=" in PT
  PT_transformed = ""
  for i in range(len(PT)):
    if PT[i] == ';':
      PT_transformed += "';'"
    elif PT[i] == '=':
      PT_transformed += "'='"
    else:
      PT_transformed += PT[i]

  # Apply prepend and append bytes
  prepend = "comment1=cooking%20MCs;userdata="
  append  = ";comment2=%20like%20a%20pound%20of%20bacon"
  PT_bytes = codecs.encode(prepend + PT_transformed + append)

  # Return result of CBC encryption
  return PT_bytes, CTR_encrypt(PT_bytes, AES_key, CTR_nonce)

'''
Perform CTR decrypt
Returns if resulting PT has ";admin=true;" substring
'''
def function2(CT_bytes, AES_key, CTR_nonce):
  PT_bytes = CTR_decrypt(CT_bytes, AES_key, CTR_nonce)
  has_string = (str(PT_bytes).find(";admin=true;") != -1)
  print("Function 2 invoked:")
  print("PT: {0} -> {1}".format(PT_bytes, has_string))
  print()
  return has_string

def main():
  # (HIDDEN) Step 0: Setup
  random_AES_key = random_bytes(AES_block_size)
  random_CTR_nonce = random_bytes(AES_block_size // 2)

  # Simple test on function1 and function2
  test_string = ";admin=true;"
  test_PT, test_CT = function1(test_string, random_AES_key, random_CTR_nonce)
  assert(not function2(test_CT, random_AES_key, random_CTR_nonce))

  # Step 1: Generate any CT and choose a block to manipulate (besides 1st block)
  # We can just use empty PT and manipulate the 2nd block (idx = 1)
  PT_bytes, CT_bytes = function1("", random_AES_key, random_CTR_nonce)

  # Step 2: Figure out the XOR difference needed to make 2nd block become ;admin=true;????
  # Since CTR uses same "stream", the needed difference is just XOR of target string with the PT_bytes
  to_xor = fixed_xor(get_block(PT_bytes, 1), b";admin=true;????")

  # Step 3: Apply XOR difference to the block before, at the appropriate indices
  modified_CT_bytes = bytearray(CT_bytes)
  for i in range(len(to_xor)):
    modified_CT_bytes[AES_block_size + i] ^= to_xor[i]
  modified_CT_bytes = bytes(modified_CT_bytes)

  # Step 4: Decrypt modified CT to get ;admin=true;
  assert(function2(modified_CT_bytes, random_AES_key, random_CTR_nonce))

if __name__ == "__main__":
  main()

