'''
URL: http://cryptopals.com/sets/2/challenges/13
Title: ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:
email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:
  A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
  B. Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
'''

from challenge_util import *

def k_v_parsing(s):
  output = {}
  for pair in s.split('&'):
    [k,v] = pair.split('=')
    output[k] = v
  return output

def profile_for(email):
  # Remove & and =
  email = email.replace('&', '')
  email = email.replace('=', '')

  # Add uid and role
  profile = "email={0}&uid=10&role=user".format(email)
  return profile

def encode_profile(PT, AES_key):
  return ECB_encrypt(PT, AES_key)

def decode_profile(CT, AES_key):
  return ECB_decrypt(CT, AES_key)

# filler = "ABC..."
def gen_step1():
  filler = ""
  while True:
    test_vec = "email={0}&uid=10&role=".format(filler)
    if len(test_vec) % AES_block_size == 0:
      idx = len(test_vec) // AES_block_size
      break
    filler += chr(len(filler) + 65)
  email = codecs.encode(filler)
  return [idx, email]

# filler = "ZYX..."
def gen_step2():
  filler = ""
  while True:
    test_vec = "email={0}".format(filler)
    if len(test_vec) % AES_block_size == 0:
      break
    filler += chr(90-len(filler))
  pad = AES_block_size - len("admin")
  email = codecs.encode(filler + "admin") + bytes([pad] * pad)
  test_vec = codecs.encode("email=") + email
  assert(len(test_vec) % AES_block_size == 0)
  idx = len(test_vec) // AES_block_size - 1
  return [idx, email]

def gen_step3(step1_CT, step1_idx, step2_CT, step2_idx):
  combined = bytearray()
  for i in range(len(step1_CT) // AES_block_size):
    if i == step1_idx:
      combined += get_block(step2_CT, step2_idx)
    else:
      combined += get_block(step1_CT, i)
  return bytes(combined)

def main():
  # Sanity check
  print("Sanity checks on implementation of k_v_parsing() and profile_for() functions")
  print(k_v_parsing("foo=bar&baz=qux&zap=zazzle"))
  print(profile_for("foo@bar.com"))
  print(profile_for("foo@bar.com&role=admin"))
  print()

  # Fix unknown random AES key
  random_AES_key = random_bytes(AES_block_size)

  # Goal: Generate "x" such that decode_profile(x) has role=admin
  # My 3-step method:
  # Step 1: Generate "email=<filler>&uid=10&role=" + "user<pad>", where "user" is in new block
  # Step 2: Generate "email=<filler>" + "admin<pad>" + "&uid=10&role=user", where "admin" is in new block
  # Step 3: Cut and paste, as suggested by challenge title

  step1_idx, step1_email = gen_step1()
  step1_PT = codecs.encode(profile_for(codecs.decode(step1_email)))
  step1_CT = encode_profile(step1_PT, random_AES_key)

  print("Step 1:")
  print("Email: {0}".format(step1_email))
  print("Offset index: {0}".format(step1_idx))
  print("Encrypted profile:\n{0}".format(step1_CT))
  print()

  step2_idx, step2_email = gen_step2()
  step2_PT = codecs.encode(profile_for(codecs.decode(step2_email)))
  step2_CT = encode_profile(step2_PT, random_AES_key)
 
  print("Step 2:")
  print("Email: {0}".format(step2_email))
  print("Offset index: {0}".format(step2_idx)) 
  print("Encrypted profile:\n{0}".format(step2_CT))
  print()

  step3_CT = gen_step3(step1_CT, step1_idx, step2_CT, step2_idx)
  step3_PT = decode_profile(step3_CT, random_AES_key)

  print("Step 3 (Cut and replace, according to offset indices, to craft an encrypted profile):")
  print("Modified encrypted profile:\n{0}".format(step3_CT))
  print()
  print("After decryption:\n{0}".format(step3_PT))
  print()

if __name__ == "__main__":
  main()
