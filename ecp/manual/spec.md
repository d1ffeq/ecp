# Documentation


This document describes protocol specification and encryption scheme. 

Algorithms used in ECP:

1. ECDH (curve P-256) 
2. ECDSA (curve P-256)
3. AES-256 (CBC mode)
4. HMAC SHA-512
5. SHA-256
6. SHA-512

Libraries used in python implementation:

1. OpenSSL (cryptographic library)
2. PyElliptic (OpenSSL wrapper)
3. Construct (data parser)
4. PyQt (GUI)

ECP design goals: 

1. Simplicity and ease of use
2. Short public keys
3. Protocol should use well-defined common algorithms and parameters for re-implementation simplicity


To communicate, users must generate keypairs and exchange public keys with each other. All keys are unique and have a special identifier - key ID. It is advised to validate IDs personally after public key exchange. After that, users can exchange encrypted messages by any channels, sign open text and files. 

Currently, there are 3 message types and 4 signature types, each signified by a 8-bit magic number. 
* Message magic numbers are multiples of 12
* Signature magic numbers are multiples of 7. 
Magic numbers chosen to have computational advantage and to fit in 8-bit unsigned integer. 

## Encrypted messages

There are three types of encrypted messages: normal, incognito and obfuscated. Normal message is the default type - it does not hide sender or receiving parties. Incognito message does not include senders public key, but list of receiving parties (if there is more than of recipient) is visible. Obfuscated message does not include identifiers and senders public key, however it is computationally harder to decrypt - since there are no IDs to determine right key, all keys are tried for decryption. 

Data strings are length-prefixed; IDs of recipients, message tokens, ephemeral ECDH key, sender public key, HMAC and signature strings are prefixed with 8-bit unsigned integer; ciphertext is prefixed with 32-bit unsigned integer. Message type and number of recipients are 8-bit numbers, so they are not prefixed. 

## Encryption scheme overview 

To encrypt payload M, following operations are performed:

1. Generate a cryptographically random string K
2. Using one part of K as AES key and other as IV, encrypt M with K, getting eM
3. Compute HMAC using eM and K
4. Generate a session elliptic curve keypair Q
5. Compute ECDH shared secret between Q and each of the recipients public keys, getting shared secrets S1, S2, S3, ... etc
6. Encrypt K for each recipient using corresponding shared secret (S1, S2, S3 and so on), getting eK1, eK2, eK3, ... etc
7. Construct message and sign with static key

For Incognito and Hidden ID message types, construction is signed by ephemeral keys.

To decrypt construction and get M:

1. Verify signature of the construction
2. Compute shared secret between session key Q and own static key, getting S
3. Decrypt corresponding eK with S, getting K
4. Verify HMAC of message using K and eM
5. Decrypt eM with K, getting M


### Message type 12

Normal message type

Scheme:


    +------------------------------------+
    |    message type                    |
    +------------------------------------+
    |    number of recipients            |
    +------------------------------------+
    |    IDs of recipients               |
    +------------------------------------+
    |    message tokens                  |
    +------------------------------------+
    |    ephemeral ECDH key              |
    +------------------------------------+
    |    sender public key               |
    +------------------------------------+
    |    ciphertext                      |
    +------------------------------------+
    |    SHA-512 HMAC of the ciphertext  |
    +------------------------------------+
    |    ECDSA signature                 |
    +------------------------------------+


### Message type 24

Incognito message type

Scheme:


    +------------------------------------+
    |    message type                    |
    +------------------------------------+
    |    number of recipients            |
    +------------------------------------+
    |    IDs of recipients               |
    +------------------------------------+
    |    message tokens                  |
    +------------------------------------+
    |    ephemeral ECDH key              |
    +------------------------------------+
    |    ciphertext                      |
    +------------------------------------+
    |    SHA-512 HMAC of the ciphertext  |
    +------------------------------------+
    |    ECDSA signature                 |
    +------------------------------------+


### Message type 36

Obfuscated message type. Contains type 12 or 24 as payload

Scheme:


    +------------------------------------+
    |    message type                    |
    +------------------------------------+
    |    number of recipients            |
    +------------------------------------+
    |    message tokens                  |
    +------------------------------------+
    |    ephemeral ECDH key              |
    +------------------------------------+
    |    ciphertext (payload)            |
    +------------------------------------+
    |    SHA-512 HMAC of the ciphertext  |
    +------------------------------------+
    |    ECDSA signature                 |
    +------------------------------------+


### Signature type 7

No timestamp, signature integrated into document with designated header (clearsign)

Scheme of signature:


    +------------------------------------------+
    |    message type                          |
    +------------------------------------------+
    |    signing party key                     |
    +------------------------------------------+
    |    ECDSA signature of text + data above  |
    +------------------------------------------+



### Signature type 14

With timestamp, signature integrated into document with designated header (clearsign)

Scheme of signature:


    +------------------------------------------+
    |    message type                          |
    +------------------------------------------+
    |    timestamp                             |
    +------------------------------------------+
    |    signing party key                     |
    +------------------------------------------+
    |    ECDSA signature of text + data above  |
    +------------------------------------------+


### Signature type 21

No timestamp, written to a separate file (detached)

Scheme of signature data:


    +------------------------------------------+
    |    message type                          |
    +------------------------------------------+
    |    signing party key                     |
    +------------------------------------------+
    |    ECDSA signature of file + data above  |
    +------------------------------------------+


### Signature type 28

With timestamp, written to a separate file (detached)

Scheme of signature data:

    +------------------------------------------+
    |    message type                          |
    +------------------------------------------+
    |    timestamp                             |
    +------------------------------------------+
    |    signing party key                     |
    +------------------------------------------+
    |    ECDSA signature of file + data above  |
    +------------------------------------------+


Parameters: 

1. ECDH/ECDSA keys are 256 bit long
2. All keys defined on P-256 curve (a.k.a. prime256v1 or secp256r1)
3. Shared secret and HMAC are derived with SHA-512 hash
4. Data encrypted with AES 256 bit in CBC mode
5. ECDSA signing is applied to SHA-256 hash

These parameters were chosen for a decent security/performance trade-off. They are commonly used in cryptographic libraries of many languages, which makes implementation in other programming languages much more convenient. 


## Keys

P-256 keys are 64 bytes (32 bytes for each X and Y points). After compression, public key becomes 33 bytes (32 bytes of X point and 1 byte of Y sign), this form is used in messages. After Base58-encoding, key becomes 44-45 charecters long, which then are prefixed with "ECP". This form is used in human-readable key exchange. 

Each key has its own ID. This identifier is formed by Base32-encoded 5 bytes of SHA-512 hash of X + Y points of a public key.

Example of Public key: 

    ECP26s8EkSaqcrZ46LeAivwweEUp8pPvNqyiohUegt6W4f1o

Key ID: YQTCK2UT

Each key can be named locally. Name is stored in "alias" option.  


## Key ring

All keys are stored in INI-style configuration files. Private user keys are called Master Keys, and are stored in file master_keyring.dat Public keys of others are called Contacts and stored in file contact_keyring.dat

Storing format: 

    [section1] 
    option1 = value1
    option2 = value2

    [section2] 
    option1 = value1
    option2 = value2

where sections are key IDs, options are private/public key and label. Key values are Base58-encoded. 

Both files are UTF-8 without BOM. 
