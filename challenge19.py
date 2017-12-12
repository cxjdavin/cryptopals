'''
URL: http://cryptopals.com/sets/3/challenges/19
Title: Break fixed-nonce CTR mode using substitutions

Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.

In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:

SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=

(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that:

CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE

And since the keystream is the same for every ciphertext:

CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't say!")

Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.

---
Don't overthink it.

Points for automating this, but part of the reason I'm having you do this is that I think this approach is suboptimal.
---
'''

from challenge_util import *
import time

def produce_CT():
  all_PT = ["SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
            "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
            "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
            "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
            "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
            "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
            "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
            "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
            "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
            "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
            "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
            "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
            "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
            "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
            "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
            "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
            "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
            "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
            "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
            "U2hlIHJvZGUgdG8gaGFycmllcnM/",
            "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
            "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
            "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
            "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
            "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
            "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
            "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
            "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
            "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
            "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
            "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
            "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
            "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
            "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
            "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
            "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]
  all_PT_bytes = [codecs.decode(codecs.encode(PT), "base64") for PT in all_PT]
  random_AES_key = random_bytes(AES_block_size)
  fixed_nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00"
  all_CT_bytes = [CTR_encrypt(PT, random_AES_key, fixed_nonce) for PT in all_PT_bytes]
  return all_PT_bytes, all_CT_bytes

'''
Parses norvig_freq.txt
Source: http://norvig.com/mayzner.html

To do: Extend this to account for frequencies instead of equal weightage
'''
def setup_freq():
  counts = dict()
  with open("norvig_freq.txt", 'r') as fin:
    for line in fin:
      line = line.split()
      for x in line:
        counts[x] = 1
  return counts

def compute_score(CT_bytes, xor_bytes, xor_indices, counts):
  assert(len(xor_bytes) == len(xor_indices))
  N = len(xor_bytes)

  score = [0 for i in range(N)]
  for i in range(len(CT_bytes)):
    if xor_indices[-1] >= len(CT_bytes[i]):
      continue

    # Decode chunk
    PT = ""
    chunk = [CT_bytes[i][j] for j in xor_indices]
    for j in range(N):
      PT_byte = chunk[j] ^ xor_bytes[j]
      # Lowercase first character to account for start of sentences
      if j == 0 and 65 <= PT_byte and PT_byte <= 90:
        PT_byte += 32
      PT += chr(PT_byte)
    
    # Update score if it is a frequent ngram
    if PT in counts.keys():
      for k in range(N):
        score[k] += counts[PT]
  return score

def main():
  all_PT_bytes, all_CT_bytes = produce_CT()

  # Note: This is similar to ECB mode since the keystream is the same for all PTs
  # i.e. CT1 xor CT2 = (PT1 xor stream) xor (PT2 xor stream) = PT1 xor PT2
  xor_len = max([len(x) for x in all_CT_bytes]) 
  counts = setup_freq()

  xor_scores = []
  for i in range(xor_len):
    xor_scores.append(dict())
    for b in range(2 ** 8):
      xor_scores[i][b] = 0

  # Compute scores
  # See comment chunk at end of file for sample run
  # Takes over an hour for a complete run
  total_start = time.time()

  # Add 1-letter frequency scores
  start = time.time()
  for bi in range(2 ** 8):
    for i in range(xor_len):
      score = compute_score(all_CT_bytes, [bi], [i], counts)
      xor_scores[i][bi] += score[0]
  end = time.time()
  print("Time taken to compute 1-letter scores: {0} seconds".format(end - start))

  # Add 2-letter frequency scores
  start = time.time()
  for i in range(xor_len-1):
    for bi, vi in xor_scores[i].items():
      if vi == 0:
        continue
      for bj, vj in xor_scores[i+1].items():
        if vj == 0:
          continue
        score = compute_score(all_CT_bytes, [bi, bj], [i, i+1], counts)
        xor_scores[ i ][bi] += score[0]
        xor_scores[i+1][bj] += score[1]
  end = time.time()
  print("Time taken to compute 2-letter scores: {0} seconds".format(end - start))

  # Add 3-letter frequency scores
  start = time.time()
  for i in range(xor_len-2):
    for bi, vi in xor_scores[i].items():
      if vi == 0:
        continue
      for bj, vj in xor_scores[i+1].items():
        if vj == 0:
          continue
        for bk, vk in xor_scores[i+2].items():
          if vk == 0:
            continue
          score = compute_score(all_CT_bytes, [bi, bj, bk], [i, i+1, i+2], counts)
          xor_scores[ i ][bi] += score[0]
          xor_scores[i+1][bj] += score[1]
          xor_scores[i+2][bk] += score[2]
  end = time.time()
  print("Time taken to compute 3-letter scores: {0} seconds".format(end - start))

  total_end = time.time()
  print("Total time taken: {0} seconds".format(total_end - total_start))

  # Guess the byte assignment which highest score for each byte in xor_len
  most_likely = bytearray()
  for i in range(xor_len):
    best = None
    best_score = -1
    for k,v in xor_scores[i].items():
      if v > best_score:
        best = k
        best_score = v
    most_likely.append(best)

  # Decode according to most likely xor stream
  decoded_bytes = []
  for i in range(len(all_CT_bytes)):
    decoded = bytearray()
    for j in range(min(xor_len,len(all_CT_bytes[i]))):
      decoded.append(all_CT_bytes[i][j] ^ most_likely[j])
    decoded_bytes.append(bytes(decoded))

  # Compare
  for i in range(len(all_PT_bytes)):
    print("Original: {0}".format(all_PT_bytes[i]))
    print("Decoded : {0}".format(decoded_bytes[i]))

if __name__ == "__main__":
  main()

'''
Sample run

Time taken to compute 1-letter scores: 0.38883280754089355 seconds
Time taken to compute 2-letter scores: 25.307722806930542 seconds
Time taken to compute 3-letter scores: 3950.395197868347 seconds
Total time taken: 3976.091878890991 seconds
Original: b'I have met them at close of day'
Decoded : b'I have met them at close of<day'
Original: b'Coming with vivid faces'
Decoded : b'Coming with vivid faces'
Original: b'From counter or desk among grey'
Decoded : b'From counter or desk among {rey'
Original: b'Eighteenth-century houses.'
Decoded : b'Eighteenth-century houses.'
Original: b'I have passed with a nod of the head'
Decoded : b'I have passed with a nod of<the!itqs'
Original: b'Or polite meaningless words,'
Decoded : b'Or polite meaningless words0'
Original: b'Or have lingered awhile and said'
Decoded : b'Or have lingered awhile and<saie'
Original: b'Polite meaningless words,'
Decoded : b'Polite meaningless words,'
Original: b'And thought before I had done'
Decoded : b'And thought before I had dore'
Original: b'Of a mocking tale or a gibe'
Decoded : b'Of a mocking tale or a gibe'
Original: b'To please a companion'
Decoded : b'To please a companion'
Original: b'Around the fire at the club,'
Decoded : b'Around the fire at the club0'
Original: b'Being certain that they and I'
Decoded : b'Being certain that they and<I'
Original: b'But lived where motley is worn:'
Decoded : b'But lived where motley is wsrn:'
Original: b'All changed, changed utterly:'
Decoded : b'All changed, changed utterle:'
Original: b'A terrible beauty is born.'
Decoded : b'A terrible beauty is born.'
Original: b"That woman's days were spent"
Decoded : b"That woman's days were spenh"
Original: b'In ignorant good will,'
Decoded : b'In ignorant good will,'
Original: b'Her nights in argument'
Decoded : b'Her nights in argument'
Original: b'Until her voice grew shrill.'
Decoded : b'Until her voice grew shrill2'
Original: b'What voice more sweet than hers'
Decoded : b'What voice more sweet than ters'
Original: b'When young and beautiful,'
Decoded : b'When young and beautiful,'
Original: b'She rode to harriers?'
Decoded : b'She rode to harriers?'
Original: b'This man had kept a school'
Decoded : b'This man had kept a school'
Original: b'And rode our winged horse.'
Decoded : b'And rode our winged horse.'
Original: b'This other his helper and friend'
Decoded : b'This other his helper and fniene'
Original: b'Was coming into his force;'
Decoded : b'Was coming into his force;'
Original: b'He might have won fame in the end,'
Decoded : b'He might have won fame in tte eoe='
Original: b'So sensitive his nature seemed,'
Decoded : b'So sensitive his nature seeqed,'
Original: b'So daring and sweet his thought.'
Decoded : b'So daring and sweet his thoight/'
Original: b'This other man I had dreamed'
Decoded : b'This other man I had dreamex'
Original: b'A drunken, vain-glorious lout.'
Decoded : b'A drunken, vain-glorious loit.'
Original: b'He had done most bitter wrong'
Decoded : b'He had done most bitter wrorg'
Original: b'To some who are near my heart,'
Decoded : b'To some who are near my heant,'
Original: b'Yet I number him in the song;'
Decoded : b'Yet I number him in the son{;'
Original: b'He, too, has resigned his part'
Decoded : b'He, too, has resigned his p}rt'
Original: b'In the casual comedy;'
Decoded : b'In the casual comedy;'
Original: b'He, too, has been changed in his turn,'
Decoded : b'He, too, has been changed ir hir!eeeee'
Original: b'Transformed utterly:'
Decoded : b'Transformed utterly:'
Original: b'A terrible beauty is born.'
Decoded : b'A terrible beauty is born.'
'''
