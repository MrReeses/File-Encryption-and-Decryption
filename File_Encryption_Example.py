## @package File_Encryption_Example
#  This project is an example of file encryption using Python. In this
#  example, Advanced Encryption Standard (AES) from the Crypto library.
#  AES uses a 16, 24, or 32-byte key to encrypt information. The bigger
#  the key, the better the encryption. In this case, the user must provide
#  the key and input file name including location. Any type of file can
#  be encrypted as far as I have tested. 
#
## \n Author: Mr. Reeses
## \n Date: 9/24/2015
## \n Version: 1.0
#
## \n Example of how to type in prompt:
## \n encrypt_file('abcde12345f6g7h8', 'C:\Users\Owner\Desktop\hello_world.txt',
#  'C:\Users\Owner\Desktop\hello_world_encrypt', 4096)

import os, random, struct
from Crypto.Cipher import AES

## This function is used to encrypt a file using AES (CBC mode) with the
#  given key.
#
#  @param key
#       The encryption key - a string that must be
#       either 16, 24 or 32 bytes long. Longer keys
#       are more secure.
#
# @param in_filename
#       Name of the input file
#
# @param out_filename
#       If None, '<in_filename>.enc' will be used.
#
# @param chunksize
#       Sets the size of the chunk which the function
#       uses to read and encrypt the file. Larger chunk
#       sizes can be faster for some files and machines.
#       chunksize must be divisible by 16.
def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):

    """ Check if the user gave an output file name. If not, then
        assign the new file with the same name as the unencrypted
        file + '.enc'
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    """ Initialize a vector to prevent repetition in encryption.
        Generate an encryptor 
    """
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))
