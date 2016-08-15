# ECP

ECP (Elliptic Curve Privacy) cryptographic tool. Allows to encrypt and sign documents/files using elliptic curve cryptography. 

## Installation 

### Linux

Install dependencies: 

    sudo apt-get install openssl python-qt4 git 

Clone repository:

    git clone https://github.com/d1ffeq/ecp.git

Run program with:

    python2 ecp.py
    
GUI will appear. To use CLI version, use:

    python2 ecp-cli.py

### Windows

Download release, unpack zip archive and run ecp.exe or ecp-cli.exe

## License

ECP is licensed under MIT License. Libraries used by ECP (pyelliptic and Construct) are MIT License. 

## Disclaimer

Although ECP uses well-known encryption algorithms, it may still be vulnerable or may contain bugs and critical cryptographical flaws. For the sake of security, use additional tools, like GPG. 