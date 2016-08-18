#!/bin/bash


# Interactive Shell script to sign text messages

# This script uses python source file - to use it with binary package,
# substitute this part of command (line 26):
#
# python2 ecp-cli.py
#
# with this:
# ./ecp-cli

# Create temporary file to store plain text
femb1="$(mktemp)"

# Message is entered in the terminal
printf 'Enter multiline text message to sign [finish input by Ctrl+D]:\n'
cat > $femb1

# Reading MasterKey ID
printf 'Enter ID of a MasterKey to sign with:\n'
read mkey

# Main command
python2 ecp-cli.py sign-message --master-key $mkey --msg $femb1 

# Removing temporary files
rm -f $femb1

# Notifying that temporary files are deleted
printf '\n\n\nDeleted %s \n\n' "$femb1"
