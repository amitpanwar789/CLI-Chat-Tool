# import rsa
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives import hashes



# def generate_keys():
#   """Generates an RSA key pair."""
#   key = rsa.generate_private_key(
#       public_exponent=65537,
#       key_size=2048,
#   )
#   public_key = key.public_key()
#   return key, public_key

# def encrypt_message(message, public_key):
#   """Encrypts a message using a public key."""
#   ciphertext = public_key.encrypt(
#       message,
#       padding.OAEP(
#           mgf=padding.MGF1(algorithm=hashes.SHA256()),
#           algorithm=hashes.SHA256(),
#           label=None
#       )
#   )
#   print(type(ciphertext))
#   return ciphertext

# def decrypt_message(ciphertext, private_key):
#   """Decrypts a message using a private key."""
#   plaintext = private_key.decrypt(
#       ciphertext,
#       padding.OAEP(
#           mgf=padding.MGF1(algorithm=hashes.SHA256()),
#           algorithm=hashes.SHA256(),
#           label=None
#       )
#   )
#   return plaintext

# if __name__ == "__main__":
#   key, public_key = generate_keys()
#   message = b"This is a secret message."
#   ciphertext = encrypt_message(message, public_key)
#   plaintext = decrypt_message(ciphertext, key)
#   print(plaintext)
# import threading


# def receive_messages(a):
#     b = input()
# a = "HI"
# ab = threading.Thread(target=receive_messages, args=(a,))
# ab.start()
# print(a)
# print("hieegsa",end='')



import getpass
import os


a = getpass.getpass()
os.system("clear")
        

