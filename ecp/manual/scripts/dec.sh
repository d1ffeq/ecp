#!/bin/bash


# Reference shell script to decrypt messages

# This script uses python source file - to use it with binary package,
# substitute this part of command (line 16):
#
# python2 ecp-cli.py
#
# with this:
# ./ecp-cli


# Main command
python2 ecp-cli.py decrypt --msg msg_file


# - Usage examples -
#
#
# For decryption, specifying keys is unnecessary, program will use appropriate keys automatically
#
# To decrypt MIME-Encoded message written in encrypted.asc, use command:
# python2 ecp-cli.py decrypt --msg encrypted.asc 
#
# To decrypt non-encoded (binary) message written in encrypted.bin, use command:
# python2 ecp-cli.py decrypt --msg encrypted.bin --binary
#
# Decrypted message will be printed in terminal. 
#
# To write decrypted text in separate file, for example, plain.txt, use command:
# python2 ecp-cli.py decrypt --msg encrypted.asc --output plain.txt
#
# As an example, command combining all options:
# python2 ecp-cli.py decrypt --msg encrypted.bin --binary --output plain.txt
#
#

