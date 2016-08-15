import hashlib
import base64
import codecs
import base58
import crypto as Crypto
from parsing import UnicodeConfigParser 
cconf = UnicodeConfigParser()
mconf = UnicodeConfigParser()




class KeyException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


class Key:
    def __init__(self, key_id = None, passwd = None):
        # If no ID provided, creates ephemeral keypair
        if key_id is None:
            self.raw_privkey, self.raw_pubkey = Crypto.generate_new_key()
            self.lib_privkey = format_privkey(self.raw_privkey, 'bin')
            self.lib_pubkey = fmt_pub(self.raw_pubkey, 'raw2lib')
            self.msg_pubkey = fmt_pub(self.raw_pubkey, 'raw2msg')
        elif not key_id is None:
            b58_priv, b58_pub = retrieve_master_keypair(key_id)
            if not passwd is None:
                self.lib_privkey = unlock_privkey(passwd, b58_priv)
            elif passwd is None:
                self.lib_privkey = base58.b58decode(b58_priv)
            self.lib_pubkey = fmt_pub(b58_pub, 'readable2lib')
            self.msg_pubkey = fmt_pub(b58_pub, 'readable2msg')


    def get_pub(self, fmt):
        '''Returns users public key in a specific format'''
        if fmt is 'msg':
            return self.msg_pubkey
        elif fmt is 'lib':
            return self.lib_pubkey


    def get_priv(self, fmt):
        '''Returns users private key in a specific format'''
        if fmt is 'raw':
            return self.raw_privkey
        elif fmt is 'lib':
            return self.lib_privkey




def format_privkey(privkey, return_form = 'bin'):
    '''Formats private key in binary or base58-encode form
    
    Concatenates Curve UID and point size - this format is required by pyelliptic'''
    if return_form is 'bin': 
        return '\x01\x9f\x00\x20' + privkey
    elif return_form is 'b58': 
        return base58.b58encode('\x01\x9f\x00\x20' + privkey)


def lock_privkey(passwd, b58_priv):
    '''Encrypts private key with password'''
    passwd_hash = hashlib.sha512(passwd.encode('utf-8')).digest()
    key_to_lock = base58.b58decode(b58_priv)
    locked_key = Crypto.encrypt(passwd_hash, key_to_lock)
    return 'encrypted_' + base58.b58encode(locked_key)


def unlock_privkey(passwd, b58_priv):
    '''Decrypts private key with password'''
    passwd_hash = hashlib.sha512(passwd.encode('utf-8')).digest()
    key_to_unlock = base58.b58decode(b58_priv[10:])
    try:
        unlocked_key = Crypto.decrypt(passwd_hash, key_to_unlock)
        return unlocked_key
    except Exception:
        e = 'Wrong password!'
        raise KeyException(e)


def key_locked(id):
    '''Checks if private key of a given ID is protected by password'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        if 'encrypted_' in mconf.get(id, 'privatekey'):
            return True
        elif not 'encrypted_' in mconf.get(id, 'privatekey'):
            return False


def change_privkey_pass(id, keypass_old, keypass_new):
    '''Decrypts encrypted private key and encrypts with new password'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        unlocked_key_old = unlock_privkey(keypass_old, mconf.get(id, 'privatekey'))
        locked_key_new = lock_privkey(keypass_new, base58.b58encode(unlocked_key_old))
        mconf.set(id, 'privatekey', locked_key_new)
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)


def set_masterkey_pass(id, keypass_new):
    '''Encrypts non-protected private key with password'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        locked_key_new = lock_privkey(keypass_new, mconf.get(id, 'privatekey'))
        mconf.set(id, 'privatekey', locked_key_new)
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)


def remove_masterkey_pass(id, keypass):
    '''Decrypts private key and writes it back unprotected'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        unlocked_key = unlock_privkey(keypass, mconf.get(id, 'privatekey'))
        mconf.set(id, 'privatekey', base58.b58encode(unlocked_key))
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)


def fmt_pub(pubkey, type, encoded=False):
    '''Public key formatting function
    
    
    Format types:
    
    "raw" type is used for ID computation (X and Y points concatenated, in binary
    representation)
    
    "msg" type is used in encrypted messages and signatures (Y sign byte and X 
    concatenated, in binary representation)
    
    "lib" types is used by pyelliptic library for cryptographic functions (2 bytes
    of Curve UID, 2 bytes of X length, X point, 2 bytes of Y length, Y point,
    in binary representation)
    
    "readable" type is used for public key exchange (Y sign and X point concatenated,
    encode in base58 encoding and prefixed with "ECP", ASCII-only characters)'''
    if type is 'lib2msg':
        x = pubkey[4:36]
        y = pubkey[38:70]
        return Crypto.point_compress(x, y)
    elif type is 'msg2lib':
        sb = pubkey[0:1]
        xb = pubkey[1:34]
        x, y = Crypto.point_decompress(sb, xb)
        return '\x01\x9f\x00\x20' + x + '\x00\x20' + y
    elif type is 'raw2lib':
        return '\x01\x9f\x00\x20' + pubkey[0:32] + '\x00\x20' + pubkey[32:64]
    elif type is 'raw2msg':
        x = pubkey[0:32]
        y = pubkey[32:64]
        return Crypto.point_compress(x, y)
    elif type is 'raw2readable':
        short = fmt_pub(pubkey, 'raw2msg')
        return 'ECP' + (base58.b58encode(short))
    elif type is 'readable2msg':
        short = pubkey[3:]
        return base58.b58decode(short)
    elif type is 'readable2lib':
        key = fmt_pub(pubkey, 'readable2msg')
        return fmt_pub(key, 'msg2lib')
    elif type is 'lib2readable':
        short = fmt_pub(pubkey, 'lib2msg')
        return 'ECP' + (base58.b58encode(short))
    elif type is 'readable2raw':
        key = base58.b58decode(pubkey[3:])
        sb = key[0:1]
        xb = key[1:34]
        x, y = Crypto.point_decompress(sb, xb)
        return x + y
    elif type is 'msg2raw':
        sb = pubkey[0:1]
        xb = pubkey[1:34]
        x, y = Crypto.point_decompress(sb, xb)
        return x + y
    elif type is 'msg2readable':
        return 'ECP' + (base58.b58encode(pubkey))




def form_key_id(pubkey_bin):
    '''Forming of key ID
    
    Uses ONLY "raw" public key type'''
    hash_pubkey = hashlib.sha512(pubkey_bin).digest()
    making_key_id = base64.b32encode(hash_pubkey[0:5])
    return making_key_id.upper()



def generate_new_master_key(passwd = None):
    '''Generates new Master Key for user
    
    If no password provided, does not encrypt private key'''
    new_privkey, new_pubkey = Crypto.generate_new_key()
    new_key_id = form_key_id(new_pubkey)
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        mconf.add_section(new_key_id)
        if passwd is None:
            mconf.set(new_key_id, 'privatekey', (format_privkey(new_privkey, 'b58'))) 
        elif not passwd is None:
            enc_privkey = lock_privkey(passwd, (format_privkey(new_privkey, 'b58')))
            mconf.set(new_key_id, 'privatekey', enc_privkey)
        mconf.set(new_key_id, 'publickey', (fmt_pub(new_pubkey, 'raw2readable')))
        mconf.set(new_key_id, 'alias', '(none)')
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)
    return new_key_id


def edit_masterkey_alias(chosen_master_edit_index, alias_new):
    '''Changes alias for a users Master Key'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        mconf.set(chosen_master_edit_index, 'alias', alias_new)
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)


def delete_master_key(id_list):
    '''Removes Master Keys, given a list of their IDs'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        for id in id_list:
            mconf.remove_section(id)
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)


def pick_any_masterkey_from_id_list(key_id_list):
    '''Given a list of IDs, picks first encounter of a found users Master Key ID
    
    Raises exception if none found'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as master_keyring:
        mconf.readfp(master_keyring)
        known_keys = mconf.sections()
        for id in known_keys:
            if id in key_id_list:
                return id
        e = 'This message is for {}, don\'t have Master Key(s) with this key ID'.format(', '.join(key_id_list))
        raise KeyException(e)


def retrieve_master_keypair(key_id):
    '''Given a key ID, retrive Master Key public/private pair
    
    Raises error if no such ID'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as master_keyring:
        mconf.readfp(master_keyring)
        known_keys = mconf.sections()
        if any(key_id in id for id in known_keys):
            return (mconf.get(key_id, 'privatekey')), (mconf.get(key_id, 'publickey'))
        elif not any(key_id in id for id in known_keys):
            e = 'This message is for {}, don\'t have Master Key with this key ID'.format(key_id)
            raise KeyException(e)


def retrieve_masterkey_id_list():
    '''Returns IDs of users Master Keys'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        masterkey_id_list = mconf.sections()
        return masterkey_id_list


def retrieve_master_alias(id):
    '''Returns alias for users Master Key'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        return (mconf.get(id, 'alias'))


def retrieve_master_key(id):
    '''Returns public key for users Master Key'''
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        return (mconf.get(id, 'publickey'))



def retrieve_contactkey_id_list():
    '''Returns IDs of Contacts'''
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        contact_key_id_list = cconf.sections()
        return contact_key_id_list


def retrieve_contact_alias(id):
    '''Returns alias for contact'''
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        return (cconf.get(id, 'alias'))


def retrieve_contact_key(id):
    '''Returns public key for contact'''
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        return (cconf.get(id, 'publickey'))


def delete_contact_key(id_list):
    '''Removes Contacts, given a list of their IDs'''
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        for id in id_list:
            cconf.remove_section(id)
    with codecs.open('keyring/contact_keyring.dat', 'wb+', 'utf-8') as cwrite:
        cconf.write(cwrite)


def add_new_contact_key(new_id, new_key):
    '''Adds new contact to contact keyring'''
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        known_contacts = cconf.sections()
        cconf.add_section(new_id)
        cconf.set(new_id, 'publickey', new_key)
        cconf.set(new_id, 'alias', '(none)')
    with codecs.open('keyring/contact_keyring.dat', 'wb+', 'utf-8') as cwrite:
        cconf.write(cwrite)


def edit_contact_alias(chosen_contact_edit_index, alias_new):
    '''Changes alias for a contact'''
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        cconf.set(chosen_contact_edit_index, 'alias', alias_new)
    with codecs.open('keyring/contact_keyring.dat', 'wb+', 'utf-8') as cwrite:
        cconf.write(cwrite)


def check_contact_identity(key_id):
    '''Checks if contact is already in the keyring'''
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as contact_keyring:
        cconf.readfp(contact_keyring)
        known_contacts = cconf.sections()
        if any(key_id in id for id in known_contacts):
            return True
        elif not any(key_id in id for id in known_contacts):
            return False

