#!/usr/bin/env python3

# AES 256 encryption/decryption using pycrypto library

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from message import print_hex, get_pretty_hex_string, print_message

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    #iv = Random.new().read(AES.block_size)
    iv = b"\x6b\xf8\xbe\x9d\xe4\x18\xb2\x52\x1e\xd8\xc5\x9d\x8d\xd1\x27\x52"
    print_message("IV ENC: {}\n".format(get_pretty_hex_string(iv.hex())),"info")
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw)


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    #enc = base64.b64decode(enc)
    iv = enc[:16]
    #print("IV DEC: {}".format(get_pretty_hex_string(iv.hex())))
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    #print_hex(cipher.decrypt(enc[16:]).hex())

    #if not check_pkcs7_padding(BLOCK_SIZE, x):
    #    return False
    return cipher.decrypt(enc[16:])


# Test case: Test_Cipher = "This is a secret message\x08\x08\x08\x08\x08\x08\x08\x08"
    
def check_pkcs7_padding(BLOCK_SIZE, text):
        
    text_len = len(text)
    # last byte, e.g. '\x08'
    padding_len = text[-1]

    #print("Check PKCS7 Padding\n\t\tTextlen: {}\n\t\tPadding_len: {} \n\t\tStringLen: {}".format(text_len,text[-1],len(text[-padding_len:])))

    # cipher can only be a multiple of BLOCK_SIZE
    if text_len % BLOCK_SIZE != 0:
        return False

    if padding_len == 0:
        return False

    if padding_len > BLOCK_SIZE:
        return False

    if padding_len != len(text[-padding_len:]):
        return False

    padding_str = text[-padding_len:]

    for b in padding_str:
        if b != text[-1]:
            return False

    return True

"""    // check the correctness of the padding bytes by counting the occurance
    $padding = substr($padded, -1 * $padsize);
    if (substr_count($padding, chr($padsize)) != $padsize)
    {
        throw new Exception("Invalid PKCS#7 padding encountered");
    }
    """




