#!/bin/bash


# Interactive Shell script to decrypt MIME-encoded messages

# This script uses python source file - to use it with binary package,
# substitute this part of command (line 22):
#
# python2 ecp-cli.py
#
# with this:
# ./ecp-cli

# Create temporary file to store encoded text
femb1="$(mktemp)"

# Message is entered in the terminal
printf 'Enter MIME-encoded message to decrypt [finish input by Ctrl+D]:\n'
cat > $femb1

# Main command
python2 ecp-cli.py decrypt --msg $femb1 

# Removing temporary files
rm -f $femb1

# Notifying that temporary files are deleted
printf '\n\n\nDeleted %s \n\n' "$femb1"
