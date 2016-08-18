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
python2 ecp-cli.py verify-message --msg msg_file


# - Usage examples -
#
#
# For decryption, specifying keys is unnecessary, program will use appropriate keys automatically
#
# To verify text signature written in signed.txt file, use command:
# python2 ecp-cli.py verify-message --msg signed.txt 
#
# To verify file signature, specify both file to check against and sigature file. 
#
# For example, to verify package.zip and its signature package.zip.sig, use command: 
# python2 ecp-cli.py verify-file --file package.zip --signature package.zip.sig
#
#