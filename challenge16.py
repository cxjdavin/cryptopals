'''
URL: http://cryptopals.com/sets/2/challenges/16
Title: CBC bitflipping attacks

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
  Completely scrambles the block the error occurs in
  Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.

Before you implement this attack, answer this question: why does CBC mode have this property?
'''

from challenge_util import *

'''
Takes in a string PT
Convert ; and = to ';' and '='
Apply prepend and append
Perform CBC encrypt
'''
def function1(PT, AES_key, CBC_IV):
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
  return CBC_encrypt(PT_bytes, AES_key, CBC_IV)

'''
Perform CBC decrypt
Returns if resulting PT has ";admin=true;" substring
'''
def function2(CT_bytes, AES_key, CBC_IV):
  PT_bytes = CBC_decrypt(CT_bytes, AES_key, CBC_IV)
  has_string = (str(PT_bytes).find(";admin=true;") != -1)
  print("Function 2 invoked:")
  print("PT: {0} -> {1}".format(PT_bytes, has_string))
  print()
  return has_string

def main():
  # (HIDDEN) Step 0: Setup
  random_AES_key = random_bytes(AES_block_size)
  random_AES_IV  = random_bytes(AES_block_size)

  # Simple test on function1 and function2
  test_string = ";admin=true;"
  test_CT = function1(test_string, random_AES_key, random_AES_IV)
  assert(not function2(test_CT, random_AES_key, random_AES_IV))

  # Step 1: Generate any CT and choose a block to manipulate (besides 1st block)
  # We can just use empty PT and manipulate the 2nd block (idx = 1)
  # 2nd CT block : "%20MCs;userdata="
  CT_bytes = function1("", random_AES_key, random_AES_IV)

  # Step 2: Figure out the XOR difference needed to make 2nd block become ;admin=true;????
  before_xoring_block1 = fixed_xor(get_block(CT_bytes, 0), b"%20MCs;userdata=")
  modified_block = fixed_xor(before_xoring_block1, b";admin=true;????")

  # Step 3: Apply XOR difference to the block before, at the appropriate indices
  modified_CT_bytes = bytearray(CT_bytes)
  for i in range(len(modified_block)):
    modified_CT_bytes[i] = modified_block[i]
  modified_CT_bytes = bytes(modified_CT_bytes)

  # Step 4: Decrypt modified CT to get ;admin=true;
  assert(function2(modified_CT_bytes, random_AES_key, random_AES_IV))

if __name__ == "__main__":
  main()
