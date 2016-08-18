#!/bin/bash


# Reference shell script to encrypt messages

# This script uses python source file - to use it with binary package,
# substitute this part of command (line 16):
#
# python2 ecp-cli.py
#
# with this:
# ./ecp-cli


# Main command
python2 ecp-cli.py encrypt --master-key YOUR_ID --contact-id THEIR_ID --msg msg_file.txt


# - Usage examples with real IDs -
#
#
# For example, your ID is BEKS3WDF and your correspondents IDs are J77DHOQV and YQTCK2UT
#
# To encrypt regular message written in send.txt for them, use command:
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV YQTCK2UT --msg send.txt
#
# To add attachment, for example, picture.jpg, use this command:
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV --msg send.txt --attachment picture.jpg
#
# Be sure to provide the right path to files you want to encrypt
#
# To encrypt message Incognito, use command: 
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV YQTCK2UT --incognito --msg send.txt 
#
# Adding attachment is possible with the same option:
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV --incognito --msg send.txt --attachment picture.jpg
#
# Although MasterKey is required for Incognito encryption command, this MasterKey is not used in message.
#
# To encrypt message with Hidden IDs, use command
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV YQTCK2UT --incognito --msg send.txt 
#
# Combining options above is possible: 
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV YQTCK2UT --incognito --hide-ids --msg send.txt 
#
# Resulting message is Incognito message with obfuscation layer to hide IDs
#
# Examples above print encrypted message in terminal - to write output in file, use command:
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV YQTCK2UT --msg send.txt --output encrypted.asc
#
# Resulting file, encrypted.asc, is MIME-encoded. If non-encoded (binary) message is required, use command: 
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV YQTCK2UT --msg send.txt --output encrypted.bin --binary
#
#
# As an example, command combining all options:
# python2 ecp-cli.py encrypt --master-key BEKS3WDF --contact-id J77DHOQV YQTCK2UT --incognito --hide-ids --binary --msg send.txt --attachment picture.jpg --output encrypted.bin 
#
#