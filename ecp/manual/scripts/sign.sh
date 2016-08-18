#!/bin/bash


# Reference shell script to sign text messages

# This script uses python source file - to use it with binary package,
# substitute this part of command (line 16):
#
# python2 ecp-cli.py
#
# with this:
# ./ecp-cli


# Main command
python2 ecp-cli.py sign-message --master-key YOUR_ID --msg msg_file.txt


# - Usage examples with real IDs -
#
#
# For example, your ID is BEKS3WDF 
#
# To sign text written in file.txt, use command:
# python2 ecp-cli.py sign-message --master-key BEKS3WDF --msg file.txt
#
# To include timestamp in text signature, use command:
# python2 ecp-cli.py sign-message --master-key BEKS3WDF --msg file.txt --timestamp
#
# Signed text will be printed in terminal. 
#
# To write signed text in separate file, for example, signed.txt, use command:
# python2 ecp-cli.py sign-message --master-key BEKS3WDF --msg file.txt --output signed.txt
#
# To sign file, for example, package.zip, use command:
# python2 ecp-cli.py sign-file --master-key BEKS3WDF --file package.zip 
#
# To include timestamp in file signature, use command:
# python2 ecp-cli.py sign-file --master-key BEKS3WDF --file package.zip --timestamp
#
# File signature will be printed in terminal. 
#
# To write file signature in a separate file, for example, package.zip.sig, use command:
# python2 ecp-cli.py sign-file --master-key BEKS3WDF --file package.zip --output package.zip.sig 
#
# Two examples for signing text and file, combining all options:
# python2 ecp-cli.py sign-message --master-key BEKS3WDF --msg file.txt --timestamp --output signed.txt
# python2 ecp-cli.py sign-file --master-key BEKS3WDF --file package.zip --timestamp --output package.zip.sig 
#
#