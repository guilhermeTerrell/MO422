from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time
import sys

class AES_RSA_sender:
    def __init__(self, AES_initVector, message):
      self.AES_initVector     = AES_initVector
      self._AES_key           = b""
      self.message2send       = message
    
    def AES_RSA_AESkeyGen(self):
      self._AES_key = AESGCM.generate_key(bit_length=256)

    def AES_RSA_encryptSimetricKey(self, receiver_public_rsa_key):
      return receiver_public_rsa_key.encrypt(self._AES_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                                   algorithm=hashes.SHA256(),
                                                                                    label=None) )
  
    def AES_RSA_encryptMessage(self):
      return AESGCM(self._AES_key).encrypt(self.AES_initVector, self.message2send, None)

    def AES_RSA_getSenderMessage(self):
      return self.message2send


class AES_RSA_receiver:
    def __init__(self, AES_initVector):
        self._rsa_private_key   = b"" # Protected variable
        self.public_key         = b"" # public key associated with private_key​
        self._AES_key           = b""
        self.AES_initVector     = AES_initVector

    def AES_RSA_RSAkeyGen(self):
      self._rsa_private_key = rsa.generate_private_key( public_exponent=65537,key_size=2048,) # 2048 bits RSA key size
      self.public_key = self._rsa_private_key.public_key()
    
    def AES_RSA_getReceiverPublicKey(self):
      return self.public_key
    
    def AES_RSA_decryptAndGetAESkey(self, encrypted_AES_key):
      self._AES_key = self._rsa_private_key.decrypt(encrypted_AES_key, padding.OAEP(
                                                                   mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                   algorithm=hashes.SHA256(),
                                                                   label=None)) 
    def AES_RSA_getPlainText(self, cipheredText):
      return AESGCM(self._AES_key).decrypt(self.AES_initVector, cipheredText, None)


def AES_RSA_benchmark():
  ######################################## Initialization #######################################
  # both Alice and Bob will use it, recomended size is 12 bytes. 
  # See here https://cryptography.io/en/latest/hazmat/primitives/aead/
  nonce = os.urandom(12)
  Alice = AES_RSA_sender(nonce, os.urandom(1024*1024)) # 1MB random message
  Bob   = AES_RSA_receiver(nonce)

  ######################################## RSA key pair gen #######################################
  # Bob generate an RSA key pair
  rsa_key_gen_start_time = time.time()
  Bob.AES_RSA_RSAkeyGen()
  rsa_key_gen_end_time = time.time()
  rsa_key_gen_total_time = rsa_key_gen_end_time - rsa_key_gen_start_time

  ########################################## key exchange ##########################################
  # Alice generates a AES-GCM simetric key
  aes_key_exchange_start_time = time.time()
  Alice.AES_RSA_AESkeyGen()
  # Alice encrypts the AES simtric key with Bob´s RSA public key
  encrypted_AES_key = Alice.AES_RSA_encryptSimetricKey(Bob.AES_RSA_getReceiverPublicKey()) 
  # Bob decrypts the encrypted AES key using his RSA private key
  Bob.AES_RSA_decryptAndGetAESkey(encrypted_AES_key)
  # At this point both Alice and Bob has the same AES simetric key and can use it to 
  # exchange messages
  aes_key_exchange_end_time = time.time()
  aes_key_exchange_total_time = aes_key_exchange_end_time - aes_key_exchange_start_time
  
  ########################################## Message encryption ######################################
  aes_msg_enc_start_time = time.time()
  ciphertext = Alice.AES_RSA_encryptMessage()
  aes_msg_enc_end_time = time.time()
  aes_msg_enc_total_time = aes_msg_enc_end_time - aes_msg_enc_start_time

  ########################################## Message decryption ######################################
  aes_msg_dec_start_time = time.time()
  plaintext  = Bob.AES_RSA_getPlainText(ciphertext)
  aes_msg_dec_end_time = time.time()
  aes_msg_dec_total_time = aes_msg_dec_end_time - aes_msg_dec_start_time
  
  if( plaintext != Alice.AES_RSA_getSenderMessage() ):
    sys.exit("decryption failed!")

  return rsa_key_gen_total_time, aes_key_exchange_total_time, aes_msg_enc_total_time, aes_msg_dec_total_time


def main():
  iterations = 1000
  rsa_array_of_total_time = [AES_RSA_benchmark() for _ in range(iterations)]
  print(f"RSA key gen average time:      {sum(x[0] for x in rsa_array_of_total_time) / iterations:.6f} seconds")
  print(f"RSA key exchange average time: {sum(x[1] for x in rsa_array_of_total_time) / iterations:.6f} seconds")
  print(f"RSA AES encrypt average time:  {sum(x[2] for x in rsa_array_of_total_time) / iterations:.6f} seconds")
  print(f"RSA AES decrypt average time:  {sum(x[3] for x in rsa_array_of_total_time) / iterations:.6f} seconds")


if __name__ == "__main__":
  main() 
  

  