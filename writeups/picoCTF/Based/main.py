#!/usr/bin/env python3

import argparse
from Crypto.Util.number import long_to_bytes

def from_decimal (x):
    return ''.join([chr(int(i)) for i in x.split()])

def from_binary (x):
    return ''.join([chr(int(i, 2)) for i in x.split()])

def from_hex (x):
    return long_to_bytes(int(x, 16)).decode()

def from_octal (x):
    return ''.join([chr(int(i, 8)) for i in x.split()])

def main ():
    parser = argparse.ArgumentParser(description = 'picoCTF challenge: Based')
    parser.add_argument('-D', help = 'decimal values')
    parser.add_argument('-B', help = 'binary values')
    parser.add_argument('-H', help = 'hex values')
    parser.add_argument('-O', help = 'octal values')

    args = parser.parse_args()
    result = ''

    if args.D:
        result = from_decimal(args.D)
    elif args.B:
        result = from_binary(args.B)
    elif args.H:
        result = from_hex(args.H)
    elif args.O:
        result = from_octal(args.O)
    
    print(result)

if __name__ == '__main__':
    main()
