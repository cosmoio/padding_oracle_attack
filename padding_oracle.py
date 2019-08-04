#!/usr/bin/env python3
"""
Fun with padding oracles
"""

__author__ = "Cosmoio"
__version__ = "0.1.0"
__license__ = "GPL"


import re,sys
import json
from message import print_logo, print_message, print_specific_block, print_hex, get_pretty_hex_string, print_result, print_long_hex
from crypto import encrypt, decrypt,check_pkcs7_padding
import string
import logging, getopt
import signal
from itertools import product, combinations, permutations

from hashlib import sha256
import timeit
from random import randint
import time
from crypto import BLOCK_SIZE
import base64
import sys
import binascii

EXIT_ERROR = -1
EXIT_SUCCESS = 1
DEBUG=False
SECRET_KEY = "91bbafc5771ef3a2f10ca302c27123f4"


def print_purpose(PROGRAM_NAME):
    print("The purpose of this program is to showcase a cryptogrpahic side-channel attack that enables a quick decryption of ciphered data via chosen-ciphertexts.")
    sys.exit(EXIT_SUCCESS)

def print_usage(PROGRAM_NAME):
    print(PROGRAM_NAME+"\n  Usage: Just run it")
    sys.exit(EXIT_ERROR)

def main():
    PROGRAM_NAME = "[ Padding Oracle ]"

    """ Main entry point of the app """
    print_logo(PROGRAM_NAME)

    # First let us encrypt secret message
    SECRET_MESSAGE= "In cryptography, a padding oracle attack is an attack which uses the padding validation of a cryptographic message to decrypt the ciphertext. In cryptography, variable-length plaintext messages often have to be padded to be compatible with the underlying cryptographic primitive."
    print_message("Encrypt: {}\n".format(SECRET_MESSAGE),"info")
    print_message("Length: {}\n".format(len(SECRET_MESSAGE)),"info")
    
    cipher = encrypt(SECRET_MESSAGE, SECRET_KEY)
    print_long_hex("Encrypted",get_pretty_hex_string(cipher.hex()))

    # Let us decrypt using our original password
    decrypted = decrypt(cipher, SECRET_KEY)
    #print_hex(decrypted.hex()) 
    print_message("Decrypted: {}\n".format(bytes.decode(decrypted)),"success")
    
    for i in range(4,0,-1):
        print_message("Starting padding oracle attack in {}\r".format(i),"info")
        time.sleep(1)
    
    padding_oracle_attack(cipher)
    
def padding_oracle_attack(cipher):
    """
    C[15]:

    C1'[15] xor I2[15] = P2'[15] = 10
    C1'[15] xor P2'[15] = I2[15] = a3 xor 10 = B3
    C1 xor I2 = P2 = bb xor b3 = 8

    C1'[15] xor I2[15] = P2'[15] = 01
    C1'[15] xor P2'[15] = I2[15] = b2 xor 01 = B3
    C1 xor I2 = P2 = bb xor b3 = 8

    C1'[15] xor I2[15] = P2'[15] = 03
    C1'[15] xor P2'[15] = I2[15] = b0 xor 03 = B3
    C1 xor I2 = P2 = bb xor b3 = 8


    C1'[15] xor I2[15] = P2'[15] = 08
    C1'[15] xor P2'[15] = I2[15] = bb xor 08 = B3
    C1 xor I2 = P2 = bb xor b3 = 8

    Assumption, all possible C1'[15] s.t. C1'[15] xor P2'[15] = I2[15] => C1 xor I2 = P2 = 0x08 

    But the padding is wrong, hence, a server would answer with a wrong padding result!

    C1[14]:

    P2'[15] = 0x02
    C1'[15] xor I2[15] = P2'[15] = 0x02 
    P2'[15] xor I2[15] = 0x02 xor 0xB3 = C1'[15]

    P2'[14] = 0x02
    C1'[14] xor I2[14] = P2'[14] = 0x02 
    P2'[14] xor I2[14] = 0x02 xor 0xXY = C1'[14]
    C1'[14] xor 0x02 = I2[14]
    C1[14] xor I2[14] = P[14]
   """ 

    hexstr = cipher.hex()

    print_message("String length: {} Blocks: {}\n".format(len(cipher), len(cipher)/BLOCK_SIZE),"info")
    
    print_long_hex("Hexstring",get_pretty_hex_string(hexstr))

    print_message("128 Bit Cipher Blocks\n","info")
    for i in range(0,int(len(cipher)/BLOCK_SIZE)):
        print("    C{}: {}\n".format(i,get_pretty_hex_string(hexstr[i*BLOCK_SIZE*2:(i+1)*BLOCK_SIZE*2])),end="")
    print("\n")    
    block_index_max = int(len(cipher)/BLOCK_SIZE)-2
    plaintext = []


    for block_index in range(block_index_max,0,-1):
        intermediate_bytes = [None] * 16
        padding_oracle_value = 0x01
        cipher = cut_off_previous_block(cipher,block_index)
        for row in range(BLOCK_SIZE-1,0,-1):
            #print_message("row: {}\n".format(row),"info")
            found_candidate = False
            for guess_byte in range(0,256):
                mutated_block = cipher[block_index*BLOCK_SIZE:(block_index+1)*BLOCK_SIZE] 
                mutated_block = bytearray(mutated_block)
                orig_byte = mutated_block[row]
                mutated_block[row] = guess_byte 

                # this is executed only if we've solved P[16], e.g. if we have to solve P[15]
                mutated_block = solve_cm_blocks(row+1,mutated_block,intermediate_bytes,padding_oracle_value)
                
                #get_pretty_hex_string(join_cipher_blocks(cipher,mutated_block,block_index).hex())
                print("Cipher Block: {} Row: {} Guessed Byte: {} Mutated block: {}\r".format(block_index,row,guess_byte,get_pretty_hex_string(mutated_block.hex())),end="\r")
                
                try:
                    decryption_oracle(join_cipher_blocks(cipher,mutated_block,block_index))
                    intermediate_byte, plain_byte, found_candidate = compute_plain_byte(block_index,row,padding_oracle_value,guess_byte,orig_byte,found_candidate)
    
                    if orig_byte != guess_byte:
                        plaintext,padding_oracle_value,intermediate_bytes,found_candidate = store_row_candidate_results(plaintext,plain_byte,padding_oracle_value,
                                                                                                                        intermediate_byte,intermediate_bytes,row,found_candidate)
                        break
                except Exception as error: # catch *all* exceptions
                    #print_message(str(error),"success") 
                    #print_message("Mutated block: {}\n".format(get_pretty_hex_string(mutated_block.hex())),"debug")
                    aa = 0

            if found_candidate == True:
                plaintext,padding_oracle_value,intermediate_bytes,found_candidate = store_row_candidate_results(plaintext,plain_byte,padding_oracle_value,
                                                                                                                intermediate_byte,intermediate_bytes,row,found_candidate)    
    
    plaintext = bytearray(plaintext[::-1])
    #print(plaintext.decode('utf-8'))
    print("\n")
    print_result("Decrypted text\n====================\n")
    print_long_hex("Hex: ",get_pretty_hex_string(plaintext.hex()))
    print_message("Plaintext: {}\n".format(str(plaintext)),"success")

def cut_off_previous_block(cipher, block_index):
    return cipher[0:(block_index+2)*BLOCK_SIZE] 

def compute_plain_byte(block_index,row,padding_oracle_value,guess_byte,orig_byte,found_candidate):
    #print_message("Candidate for C{}[{}]' assuming P{}[{}]' is {}\n".format(block_index-1,block_index,row,row+1,hex(padding_oracle_value)),"success")
    intermediate_byte = guess_byte ^ padding_oracle_value
    plain_byte = orig_byte ^ intermediate_byte
    #print_message("Calculating P{}[{}], P': {} C': {} I: {} C: {}\n".format(block_index,row,hex(padding_oracle_value),hex(guess_byte),hex(intermediate_byte),hex(orig_byte)),"info")
    #print_message("Plain byte: {}\n".format(hex(plain_byte)),"success")
    found_candidate = True
    return intermediate_byte,plain_byte,found_candidate


def store_row_candidate_results(plaintext,plain_byte,padding_oracle_value,intermediate_byte,intermediate_bytes,row,found_candidate):
    plaintext.append(plain_byte)
    padding_oracle_value+=1
    intermediate_bytes[row] = intermediate_byte
    found_candidate = False
    return plaintext,padding_oracle_value,intermediate_bytes,found_candidate

def solve_cm_blocks(row,mutated_block,intermediate_bytes,padding_oracle_value):
    # this is executed only if we've solved P[16], e.g. if we have to solve P[15]
    for m in range(row,BLOCK_SIZE):
        # set C1'[m], depending on padding value
        mutated_block[m] = intermediate_bytes[m] ^ padding_oracle_value
        #print_message("m: {}, intermediate_bytes[m]: {} mutated_block[m]: {} assumed_padding: {}\n".format(m,hex(intermediate_bytes[m]),hex(mutated_block[m]),padding_oracle_value),"log")
    return mutated_block


def decryption_oracle(cipher):
    decrypted = decrypt(cipher, SECRET_KEY)
    #print_message("Decrypted: {}\n".format(get_pretty_hex_string(decrypted.hex())),"log")    
    if not check_pkcs7_padding(BLOCK_SIZE, decrypted):
        raise Exception("Padding not valid: {}\r".format(decrypted[-1]))
    #print(decrypted)


def join_cipher_blocks(cipher, mutated_block, block_index):
    """print("mutated block:")
    print_hex(mutated_block.hex())
    print("before block:")
    print_hex(cipher[:(block_index)*BLOCK_SIZE].hex())
    print("after block:")
    print_hex(cipher[(block_index+1)*BLOCK_SIZE:].hex())"""
    cipher = cipher[:(block_index)*BLOCK_SIZE] + mutated_block + cipher[(block_index+1)*BLOCK_SIZE:]
    return cipher


def exit_gracefully(signum, frame):
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
    signal.signal(signal.SIGINT, ORIGINAL_SIGINT)

    try:
        if input("\nReally quit? (y/n)> ").lower().startswith('y'):
            sys.exit(EXIT_SUCCESS)

    except KeyboardInterrupt:
        print("Ok ok, quitting")
        sys.exit(EXIT_SUCCESS)    

if __name__ == "__main__":
    """ This is executed when run from the command line """
    ORIGINAL_SIGINT = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_gracefully)
    main()



        
