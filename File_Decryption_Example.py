## @package File_Decryption_Example
#  This project is an example of file decryption using Python. In this
#  example, Advanced Encryption Standard (AES) from the Crypto library.
#  AES uses a 16, 24, or 32-byte key to decrypt information. In this case, the user must provide
#  the key and input file name including location. Any type of file can
#  be encrypted as far as I have tested. 
#
## \n Author:  Mr. Reeses
## \n Date:    9/24/2015
## \n Version: 1.0
#
## \n Example of how to type in prompt:
## \n decrypt_file('abcde12345f6g7h8', 'C:\Users\Owner\Desktop\hello_world_encrypt.txt',
#  'C:\Users\Owner\Desktop\hello_world_decrypt', 4096)

import os, random, struct
from Crypto.Cipher import AES

## This function is used to decrypt a file using AES (CBC mode) with the
#  given key that was used to encrypt the file.
#
#  @param key
#       The decryption key - a string that must be
#       either 16, 24 or 32 bytes long. Longer keys
#       are more secure.
#
# @param in_filename
#       Name of the encrypted input file. <in_filename>.enc
#
# @param out_filename
#       If None, '<in_filename>' will be used.
#
# @param chunksize
#       Sets the size of the chunk which the function
#       uses to read and encrypt the file. Larger chunk
#       sizes can be faster for some files and machines.
#       chunksize must be divisible by 16.

def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):

    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
  
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
