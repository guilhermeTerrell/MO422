from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time
import sys

class AES_x25519_Person:
    def __init__(self, msg, nonce):
        self._private_key       = b""  # Protected variable
        self.public_key         = b""  # public key associated with private_key​
        self.x25519_shared_key  = b""
        self.x25519_derived_key = b""
        self.message2send       = msg
        self.AES_initVector     = nonce


    def AES_x25519_keyGen(self):
      self._private_key = X25519PrivateKey.generate()
      self.public_key = self._private_key.public_key()

    def AES_x25519_getPublicKey(self):
       return self.public_key
    
    def AES_x25519_setSharedKey(self, other_part_public_key):
       self.x25519_shared_key = self._private_key.exchange(other_part_public_key)

    def AES_x25519_getSharedKey(self):
       return self.x25519_shared_key
    
    def AES_x25519_setDerivedKey(self, hash_algorithm, random_salt, key_lenght, info):
       self.x25519_derived_key = HKDF( algorithm=hash_algorithm, 
                                       length=key_lenght,
                                       salt=random_salt, 
                                       info=info,).derive(self.x25519_shared_key)

    def AES_x25519_getDerivedKey(self):
       return self.x25519_derived_key
    
    def AES_x25519_getSenderMsg(self):
      return self.message2send
   
def AES_x25519_benchmark():
  ######################################## Initialization #######################################
  # As sugested at the cryptography library documentation,
  # AES_key will be randomly generated using AESGCM.generate_key(bit_length=256)
  #  and AES_initVector will be randomly generated using system’s provided random 
  # number generator, which is available as os.urandom().
  # See more info here: https://cryptography.io/en/latest/random-numbers/
  nonce = os.urandom(16) # both Alice and Bob will use it
  Alice = AES_x25519_Person(os.urandom(1024*1024), nonce) # 1MB random message
  Bob   = AES_x25519_Person(b"", nonce)
  
  ######################################## x25519 key pair gen ####################################
  x25519_key_gen_start_time = time.time() 
  Alice.AES_x25519_keyGen()
  Bob.AES_x25519_keyGen()
  x25519_key_gen_end_time = time.time()
  x25519_key_gen_total_time = x25519_key_gen_end_time - x25519_key_gen_start_time

  ########################################## key exchange ##########################################
  x25519_key_exchange_start_time = time.time()
  random_salt = os.urandom(16) # 128 bits of salt needs not to be secret, should have the same 
                               # amount of bits of the security level.
                               # More info here: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.hkdf.HKDF
  key_len = 32 # key lenght of 32 bytes = 256 bits
  hash_algorithm = hashes.SHA256()
  Alice.AES_x25519_setSharedKey(Bob.AES_x25519_getPublicKey())
  Alice.AES_x25519_setDerivedKey(hash_algorithm, random_salt, key_len)
  Bob.AES_x25519_setSharedKey(Alice.AES_x25519_getPublicKey())
  Bob.AES_x25519_setDerivedKey(hash_algorithm, random_salt, key_len)
  x25519_key_exchange_end_time = time.time()
  x25519_key_exchange_total_time = x25519_key_exchange_end_time - x25519_key_exchange_start_time

  ########################################## Message encryption ######################################
  # Alice encrypt the message
  x25519_encrypt_start_time = time.time()
  ciphertext = AESGCM(Alice.AES_x25519_getDerivedKey()).encrypt(nonce, Alice.AES_x25519_getSenderMsg(), None)
  x25519_encrypt_end_time = time.time()
  x25519_encrypt_total_time = x25519_encrypt_end_time - x25519_encrypt_start_time
  
  ########################################## Message decryption ######################################
  # Bob decrypt the message
  x25519_decrypt_start_time = time.time()
  plaintext = AESGCM(Bob.AES_x25519_getDerivedKey()).decrypt(nonce, ciphertext, None)
  x25519_decrypt_end_time = time.time()
  x25519_decrypt_total_time = x25519_decrypt_end_time - x25519_decrypt_start_time

  if( plaintext != Alice.AES_x25519_getSenderMsg() ):
    sys.exit("decryption failed!")

  return x25519_key_gen_total_time, x25519_key_exchange_total_time, x25519_encrypt_total_time, x25519_decrypt_total_time

def main():
  iterations = 1000
  x25519_array_of_total_time = [AES_x25519_benchmark() for _ in range(iterations)]
  print(f"X25519 key gen average time:        {sum(x[0] for x in x25519_array_of_total_time) / iterations:.6f} seconds")
  print(f"X25519 key exchange average time:   {sum(x[1] for x in x25519_array_of_total_time) / iterations:.6f} seconds")
  print(f"X25519 AES encryption average time: {sum(x[2] for x in x25519_array_of_total_time) / iterations:.6f} seconds")
  print(f"X25519 AES decryption average time: {sum(x[3] for x in x25519_array_of_total_time) / iterations:.6f} seconds")

if __name__ == "__main__":
  main()



 