#!/usr/bin/env python3

from colorama import init, Fore, Style
import os, sys
import datetime

def print_logo(program_name):
    rows, columns = os.popen('stty size', 'r').read().split()
    size = int(int(columns)/1.5)
    print("\n\n"+Style.BRIGHT+Fore.YELLOW+program_name.center(size,"#")+"\n")
    print(Style.RESET_ALL)
    
def print_message(message, message_type):
    if message_type == "info":
        print(Style.BRIGHT + Fore.BLUE + "[*] " + Style.RESET_ALL + message,end='')
    if message_type == "warning":
        print(Style.BRIGHT + Fore.YELLOW + "[!] " + Style.RESET_ALL + message,end='')
    if message_type == "success":
        print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + message,end='')
    if message_type == "error":
        print(Style.BRIGHT + Fore.RED + "[!] " + Style.RESET_ALL + message,end='')
    if message_type == "log":
        print(Style.BRIGHT + Fore.WHITE + "[~] " + Style.RESET_ALL + message,end='')

def print_result(message):
    print(Style.BRIGHT + Fore.GREEN + "[+] " + message,end='')

def print_long_hex(header,hexstring):
    size = 16*3
    print_message(header+"\n","info")

    rows = int(len(hexstring)/size)
    for i in range(0,rows):
        print("{:>52s}".format(hexstring[i*size:(i+1)*size]),end="\n") 



def print_specific_block(cipher_test, block_num,BLOCK_SIZE):
    hexstr = cipher_test.hex()
    print("C{}: ".format(block_num),end='')
    print_hex(hexstr[block_num*BLOCK_SIZE:block_num*BLOCK_SIZE+BLOCK_SIZE])

def print_hex(hexstr):
    print(':'.join(hexstr[i:i+2] for i in range(0, len(hexstr), 2)))

def get_pretty_hex_string(hexstr):
    return ':'.join(hexstr[i:i+2] for i in range(0, len(hexstr), 2))

def lr_justify(left, right, width):
    return '{}{}{}'.format(left, ' '*(width-len(left+right)), right)
