# 1-prototype/crypto.py
# command line application to encrypt/decrypt messages
# usage: crypto.py encrypt|decrypt payload

import sys
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16

# encrypt encrypts payload using AES-CFB(key, iv) and returns it in base64
def encrypt(payload, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend)
    enc = cipher.encryptor()
    ciphertext = enc.update(payload) + enc.finalize()
    return b64encode(ciphertext)


# decrypt decodes the payload from base64 and decrypts with AES-CFB(key, iv)
def decrypt(payload, key, iv):
    decoded = b64decode(payload)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend)
    dec = cipher.decryptor()
    return dec.update(decoded) + dec.finalize()


def main():
    if len(sys.argv) != 3:
        print "invalid arguments - usage: crypto.py encrypt|decrypt payload"
        sys.exit(2)

    key = "0123456789012345"
    iv = "9876543210987654"

    # read argument 2, it must encrypt or decrypt
    action = sys.argv[1]
    payload = sys.argv[2]

    if action == "encrypt":
        print encrypt(payload, key, iv)
    elif action == "decrypt":
        print decrypt(payload, key, iv)
    else:
        print "first argument can only be encrypt or decrypt"

if __name__ == "__main__":
    main()
