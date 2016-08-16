import argparse
import getpass
import os
import sys
import crypto as Crypto
import keyfmt as KeyFormatting
import messaging as Messaging
import parsing as Parsing





'''Checking if encryption/decryption directories exist'''
frozen = getattr(sys,'frozen', None)
def check_decrypt_dir():
    '''Checking if /decryption/ directory exists'''
    if 'win32' in sys.platform or 'win64' in sys.platform:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.dirname(sys.executable)
        else:
            localadditionpath = os.path.dirname(__file__)
        decryptpath = localadditionpath + '/decrypted/'
        norm_decrypt_path = os.path.normpath(decryptpath)
        try: 
            os.makedirs(norm_decrypt_path)
        except OSError:
            if not os.path.isdir(norm_decrypt_path):
                raise
    else: 
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.abspath(sys.executable)
        else:
            localadditionpath = os.path.abspath(__file__)
        decryptpath = os.path.dirname(localadditionpath) + '/decrypted/'
        norm_decrypt_path = os.path.normcase(decryptpath)
        if not os.path.isdir(norm_decrypt_path):
            os.makedirs(norm_decrypt_path)


def check_encrypt_dir():
    '''Check if /encrypted/ directory exists'''
    if 'win32' in sys.platform or 'win64' in sys.platform:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.dirname(sys.executable)
        else:
            localadditionpath = os.path.dirname(__file__)
        encryptpath = localadditionpath + '/encrypted/'
        norm_encrypt_path = os.path.normcase(encryptpath)
        try: 
            os.makedirs(norm_encrypt_path)
        except OSError:
            if not os.path.isdir(norm_encrypt_path):
                raise
    else: 
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.abspath(sys.executable)
        else:
            localadditionpath = os.path.abspath(__file__)
        encryptpath = os.path.dirname(localadditionpath) + '/encrypted/'
        norm_encrypt_path = os.path.normcase(encryptpath)
        if not os.path.isdir(norm_encrypt_path):
            os.makedirs(norm_encrypt_path)


def check_keyring_files():
    '''Check if /keyring/ directory and keyring files exists'''
    if 'win32' in sys.platform or 'win64' in sys.platform:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.dirname(sys.executable)
        else:
            localadditionpath = os.path.dirname(__file__)
        keyring_path = localadditionpath + '/keyring/'
        norm_keyring_path = os.path.normcase(keyring_path)
        try:
            os.makedirs(norm_keyring_path)
        except OSError:
            if not os.path.isdir(norm_keyring_path):
                raise
        open('keyring/master_keyring.dat', 'a').close()
        open('keyring/contact_keyring.dat', 'a').close()
    else:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.abspath(sys.executable)
        else:
            localadditionpath = os.path.abspath(__file__)
        keyring_path = os.path.dirname(localadditionpath) + '/keyring/'
        norm_keyring_path = os.path.normcase(keyring_path)
        if not os.path.isdir(norm_keyring_path):
            os.makedirs(norm_keyring_path)
        open('keyring/master_keyring.dat', 'a+').close()
        open('keyring/contact_keyring.dat', 'a+').close()


'''Check if data folders exist'''
check_decrypt_dir()
check_encrypt_dir()
check_keyring_files()

'''Simple test for PRNG'''
if Crypto.run_test() is False:
    sys.exit()


class PathException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


class IDException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


def resolve_masterkey_pass(your_id):
    '''Resolves Master Key password using getpass'''
    if KeyFormatting.key_locked(your_id) is True:
        keypass = getpass.getpass(prompt = 'Enter password for key {}:'.format(your_id))
        return keypass
    elif KeyFormatting.key_locked(your_id) is False:
        return None


def encrypt_message(args):
    '''Encryption function'''
    try:
        text_message = read_file(args.msg)
        check_masterkey_id(args.master_key)
        check_contact_id(args.id)
        keypass = resolve_masterkey_pass(your_id = args.master_key)
        if not args.incognito: 
            m = Messaging.EncryptMessage(list(set(args.id)),
                                        args.master_key,
                                        keypass)
            enc_msg, msg_name = m.encrypt_normal(text_message)
        elif args.incognito: 
            m = Messaging.EncryptMessage(list(set(args.id)),
                                        args.master_key,
                                        keypass)
            enc_msg, msg_name = m.encrypt_incognito(text_message)
        if args.hide_ids:
            m = Messaging.EncryptMessage(list(set(args.id)),
                                        args.master_key,
                                        keypass)
            enc_msg, msg_name = m.encrypt_obfuscated(enc_msg)
        if not args.binary:
            enc_msg = Messaging.message_encode(enc_msg)
        if not args.output:
            print_message('Message:\n' + ('--------\n\n') + enc_msg)
        elif args.output:
            write_file(args.output, enc_msg)
            print_message('Encrypted message to: ' + args.output)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)
    except PathException, (instance):
        print_error(instance.parameter)
    except IDException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))


def decrypt_message(args):
    '''Main decryption function'''
    try: 
        message_text = read_file(args.msg)
        if not args.binary:
            message = Messaging.message_decode(message_text)
        elif args.binary:
            message = message_text
        decrypting(message)
    except Messaging.DecryptException, (instance): 
        print_error(instance.parameter)
    except Messaging.DecodeException, (instance): 
        print_error(instance.parameter)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)
    except Parsing.ParserException, (instance):
        print_error(instance.parameter)
    except PathException, (instance):
        print_error(instance.parameter)
    except IDException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))


def decrypting(message, keypass = None):
    '''Actual decryption function'''
    msg_type = Messaging.get_message_type(message)
    if msg_type is 'normal':
        id_list = Parsing.Parser().parse_rec_list(message)
        your_id = KeyFormatting.pick_any_masterkey_from_id_list(id_list)
        keypass = resolve_masterkey_pass(your_id)
        m = Messaging.DecryptMessage(your_id, keypass)
        text, status, info = m.decrypt_normal(message)
    elif msg_type is 'incognito':
        id_list = Parsing.Parser().parse_rec_list(message)
        your_id = KeyFormatting.pick_any_masterkey_from_id_list(id_list)
        keypass = resolve_masterkey_pass(your_id)
        m = Messaging.DecryptMessage(your_id, keypass)
        text, status, info = m.decrypt_incognito(message)
    elif msg_type is 'obfuscated':
        master_key_list = KeyFormatting.retrieve_masterkey_id_list()
        for key_id in master_key_list: 
            keypass = resolve_masterkey_pass(your_id = key_id)
            m = Messaging.DecryptMessage(key_id, keypass)
            decrypted_payload = m.decrypt_obfuscated(message)
            if not decrypted_payload is None: 
                decrypting(decrypted_payload, keypass)
                return
            elif decrypted_payload is None:
                print_message('Failed to decrypt with {} '.format(key_id) +\
                'Attempting to decrypt with next key...')
    elif type is 'unknown': 
        print_error('Not an ECP message!')
        return
    print_message(status + '\n\n' + info)
    if args.output: 
        write_file(args.output, text)
        print_message('Decrypted message to: ' + args.output)
    elif not args.output:
        print_message('Message:\n' + ('--------\n\n') + text)


def write_file(path, data):
    '''Checks if output directory exists and writes file to it'''
    dir_path = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(dir_path):
        e = 'No such directory: {}'.format(dir_path)
        raise PathException(e)
    with open(path, 'wb') as f:
        f.write(data)


def write_signed(path, data):
    '''Checks if output directory exists and writes UTF-8 encoded file to it'''
    dir_path = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(dir_path):
        e = 'No such directory: {}'.format(dir_path)
        raise PathException(e)
    with open(path, 'wb') as f:
        f.write(data.encode('utf-8') + '\n')


def read_file(path):
    '''Checks if directory exists and reads file'''
    dir_path = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(dir_path):
        e = 'No such directory: {}'.format(dir_path)
        raise PathException(e)
    with open(path, 'rb') as f:
        data = f.read()
    return data


def read_document(path):
    '''Checks if directory exists and reads file in universal newline mode'''
    dir_path = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(dir_path):
        e = 'No such directory: {}'.format(dir_path)
        raise PathException(e)
    with open(path, 'rU') as f:
        data = f.read()
    return data


def sign_message(args):
    '''Text signing function'''
    try:
        check_masterkey_id(args.master_key)
        text_message = read_document(args.msg)
        if not args.timestamp: 
            keypass = resolve_masterkey_pass(your_id = args.master_key)
            m = Messaging.SignData(args.master_key, keypass)
            signed_text = m.sign_clearsign(text_message)
        elif args.timestamp: 
            keypass = resolve_masterkey_pass(your_id = args.master_key)
            m = Messaging.SignData(args.master_key, keypass)
            signed_text = m.sign_clearsign_t(text_message)
        print_message('Signed message with key: ' + args.master_key)
        if args.output: 
            write_signed(args.output, signed_text)
        elif not args.output:
            print_message('Message:\n' + ('--------\n\n') + signed_text)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)
    except PathException, (instance):
        print_error(instance.parameter)
    except IDException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))


def sign_file(args):
    '''File signing function'''
    try:
        check_masterkey_id(args.master_key)
        file_data = read_file(args.file)
        if not args.timestamp:
            keypass = resolve_masterkey_pass(your_id = args.master_key)
            m = Messaging.SignData(args.master_key, keypass)
            file_sig = m.sign_detached(file_data)
        elif args.timestamp: 
            keypass = resolve_masterkey_pass(your_id = args.master_key)
            m = Messaging.SignData(args.master_key, keypass)
            file_sig = m.sign_detached_t(file_data)
        print_message('Signed file with key: ' + args.master_key)
        if args.output: 
            write_file(args.output, file_sig)
            print_message('Wrote sigature to: ' + args.output)
        elif not args.output:
            print_message('Signature:\n' + ('----------\n\n') + file_sig)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)
    except PathException, (instance):
        print_error(instance.parameter)
    except IDException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))


def verify_message(args):
    '''Text signature verification function'''
    try: 
        message_text = read_file(args.msg)
        data, sig = Messaging.msg_signature_decode(message_text)
        sig_type = Messaging.get_signature_type(sig)
        if sig_type is 'clearsign':
            m = Messaging.VerifySignature()
            status, info = m.verify_clearsigned(data, sig)
            print_message(status + '\n\n' + info)
        elif sig_type is 'clearsign_t': 
            m = Messaging.VerifySignature()
            status, info = m.verify_clearsigned_t(data, sig)
            print_message(status + '\n\n' + info)
        elif sig_type is 'unknown':
            print_error('Not an ECP signature!')
    except Messaging.DecryptException, (instance): 
        print_error(instance.parameter)
    except Messaging.DecodeException, (instance): 
        print_error(instance.parameter)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)
    except Parsing.ParserException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return


def verify_file(args):
    '''File signature verification function'''
    try:
        data = read_file(args.file)
        sig_file_data = read_file(args.sig)
        sig = Messaging.file_signature_decode(sig_file_data)
        sig_type = Messaging.get_signature_type(sig)
        if sig_type is 'detached': 
            m = Messaging.VerifySignature()
            status, info = m.verify_detached(data, sig)
            print_message(status + '\n\n' + info)
        elif sig_type is 'detached_t':
            m = Messaging.VerifySignature()
            status, info = m.verify_detached_t(data, sig)
            print_message(status + '\n\n' + info)
        elif sig_type is 'unknown':
            print_error('Not an ECP signature!')
    except Messaging.DecryptException, (instance): 
        print_error(instance.parameter)
    except Messaging.DecodeException, (instance): 
        print_error(instance.parameter)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)
    except Parsing.ParserException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return


def print_masterkeys(args):
    '''Prints users Master Keys'''
    master_id_list = KeyFormatting.retrieve_masterkey_id_list()
    s = u'Master keys:\n\n'
    for id in master_id_list:
        alias = KeyFormatting.retrieve_master_alias(id)
        pub = KeyFormatting.retrieve_master_key(id)
        s += u'[{}]\n    Public key: {}\n    Alias:      {}\n\n'.format(id, pub, alias)
    print_message(s)


def gen_masterkey(args):
    '''Generates new Master Key'''
    keypass = getpass.getpass(prompt = 'Enter password for a new Master Key:')
    if not keypass:
        keypass = None
    new_key_id = KeyFormatting.generate_new_master_key(passwd = keypass)
    print_message('Generated new key {}, edit alias for usability'.format(new_key_id))


def remove_masterkey_pass(args):
    '''Removes password protection from a Master Key'''
    try:
        check_masterkey_id(args.master_key)
        if KeyFormatting.key_locked(args.master_key) is True:
            keypass_new = getpass.getpass(prompt = 'Enter password for a key {}: '.format(args.master_key))
            KeyFormatting.remove_masterkey_pass(args.master_key, keypass_new)
        elif KeyFormatting.key_locked(args.master_key) is False:
            print_error('Cannot remove password - key is already unprotected')
            return
        print_message('Password has been removed for key: {}'.format(args.master_key))
    except IDException, (instance): 
        print_error(instance.parameter)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)


def set_masterkey_pass(args):
    '''Sets password for Master Key'''
    try:
        check_masterkey_id(args.master_key)
        if KeyFormatting.key_locked(args.master_key) is True:
            keypass_old = getpass.getpass(prompt = 'Enter old password for a key {}: '.format(args.master_key))
            keypass_new = getpass.getpass(prompt = 'Enter new password for a key {}: '.format(args.master_key))
            KeyFormatting.change_privkey_pass(args.master_key, keypass_old, keypass_new)
        elif KeyFormatting.key_locked(args.master_key) is False:
            keypass_new = getpass.getpass(prompt = 'Enter new password for a key {}: '.format(args.master_key))
            KeyFormatting.set_masterkey_pass(args.master_key, keypass_new)
        print_message('New password has been set for key: {}'.format(args.master_key))
    except IDException, (instance): 
        print_error(instance.parameter)
    except KeyFormatting.KeyException, (instance):
        print_error(instance.parameter)


def del_masterkey(args):
    '''Removes chosen Master Keys'''
    try:
        check_masterkey_id(list(set(args.id)))
    except IDException, (instance): 
        print_error(instance.parameter)
        return
    KeyFormatting.delete_master_key(list(set(args.id)))
    print_message('Key(s) {} deleted'.format(', '.join(list(set(args.id)))))


def print_contacts(args):
    '''Prints all Contacts'''
    s = u'Contact keys:\n\n'
    contact_id_list = KeyFormatting.retrieve_contactkey_id_list()
    for id in contact_id_list:
        alias = KeyFormatting.retrieve_contact_alias(id)
        pub = KeyFormatting.retrieve_contact_key(id)
        s += u'[{}]\n    Public key: {}\n    Alias:      {}\n\n'.format(id, pub, alias)
    print_message(s)


def add_contactkey(args):
    '''Adds Contact public key to keyring'''
    validation = Crypto.check_pubkey(args.pubkey)
    if validation is True:
        new_key_raw = KeyFormatting.fmt_pub(args.pubkey, 'readable2raw')
        new_key_id = KeyFormatting.form_key_id(new_key_raw)
        if KeyFormatting.check_contact_identity(new_key_id) is True:
            print_message('This key is already in key ring!')
        elif KeyFormatting.check_contact_identity(new_key_id) is False:
            KeyFormatting.add_new_contact_key(new_key_id, args.pubkey)
            print_message('New contact added: {}, edit alias for usability'.format(new_key_id))
            if args.alias:
                KeyFormatting.edit_contact_alias(new_key_id, args.alias)
    elif validation is False:
        print_message('Invalid contact key!')


def del_contactkey(args):
    '''Removes chosen Contacts'''
    try:
        check_contact_id(list(set(args.id)),)
    except IDException, (instance): 
        print_error(instance.parameter)
        return
    KeyFormatting.delete_contact_key(list(set(args.id)),)
    print_message('Key(s) {} deleted'.format(', '.join(list(set(args.id)))))


def edit_contactalias(args):
    '''Changes contact alias'''
    try:
        check_contact_id(args.contact_id)
    except IDException, (instance): 
        print_error(instance.parameter)
        return
    KeyFormatting.edit_contact_alias(args.contact_id, args.alias)
    print_message('Changed alias for contact key {}'.format(args.contact_id))


def edit_masterkeyalias(args):
    '''Changes Master Key alias'''
    try:
        check_masterkey_id(args.master_key)
    except IDException, (instance): 
        print_error(instance.parameter)
        return
    KeyFormatting.edit_masterkey_alias(args.master_key, args.alias)
    print_message('Changed alias for Master Key {}'.format(args.master_key))


def check_contact_id(ids_to_check):
    '''Checks if chosen contacts ID is in the keyring'''
    contact_id_list = KeyFormatting.retrieve_contactkey_id_list()
    if isinstance(ids_to_check, basestring):
        if not ids_to_check in contact_id_list:
            e = 'No such key: {}'.format(ids_to_check)
            raise IDException(e)
    else:
        for id in ids_to_check:
            if not id in contact_id_list:
                e = 'No such key: {}'.format(id)
                raise IDException(e)
            

def check_masterkey_id(ids_to_check):
    '''Checks if chosen Master Keys ID is in the keyring'''
    master_id_list = KeyFormatting.retrieve_masterkey_id_list()
    if isinstance(ids_to_check, basestring):
        if not ids_to_check in master_id_list:
            e = 'No such key: {}'.format(ids_to_check)
            raise IDException(e)
    else:
        for id in ids_to_check:
            if not id in master_id_list:
                e = 'No such key: {}'.format(id)
                raise IDException(e)


def print_message(msg):
    '''Prints a string with newlines
    
    Silent if no verbose option provided'''
    if args.no_verbose is True:
        pass
    elif args.no_verbose is False:
        print '\n\n' + msg + '\n\n'


def print_error(msg):
    '''Prints error in consistent form
    
    Silent if no verbose option provided'''
    if args.no_verbose is True:
        pass
    elif args.no_verbose is False:
        prog_name = os.path.basename(sys.argv[0])
        print '{}: error: {}\n'.format(prog_name, msg)




arg_parser = argparse.ArgumentParser(description = 'ECP cryptographic tool')
subparsers = arg_parser.add_subparsers(help = 'Sub-command help')


parser_encrypt = subparsers.add_parser('encrypt', 
    help = 'Encrypt message')
parser_encrypt.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify master key to encrypt messages with')
parser_encrypt.add_argument('--msg',
    type = str,
    required = True,
    help = 'Specify text message file to encrypt')
parser_encrypt.add_argument('--output',
    type = str,
    help = 'Specify output file')
parser_encrypt.add_argument('--contact-id',
    dest = 'id',
    nargs = '+',
    type = str,
    required = True,
    help = 'Specify contacts to encrypt message for')
parser_encrypt.add_argument('--incognito', 
    action = 'store_true', 
    help = 'Do not include identifiers in encrypted message')
parser_encrypt.add_argument('--hide-ids', 
    action = 'store_true', 
    help = 'Obfuscate IDs in encrypted message')
parser_encrypt.add_argument('--binary', 
    action = 'store_true', 
    help = 'Do not MIME-encode encrypted message')
parser_encrypt.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_encrypt.set_defaults(func = encrypt_message)


parser_decrypt = subparsers.add_parser('decrypt', 
    help = 'Decrypt message')
parser_decrypt.add_argument('--msg',
    type = str,
    required = True,
    help = 'Specify text message file to decrypt')
parser_decrypt.add_argument('--output',
    type = str,
    help = 'Specify output file for decrypted message')
parser_decrypt.add_argument('--binary', 
    action = 'store_true', 
    help = 'Decrypt binary (not encoded) message')
parser_decrypt.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_decrypt.set_defaults(func = decrypt_message)


parser_signmsg = subparsers.add_parser('sign-message', 
    help = 'Sign message')
parser_signmsg.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify master key to sign messages with')
parser_signmsg.add_argument('--msg', 
    type = str,
    required = True,
    help = 'Specify text document to sign')
parser_signmsg.add_argument('--output',
    type = str,
    help = 'Specify output file for signed message')
parser_signmsg.add_argument('--timestamp', 
    action = 'store_true', 
    help = 'Include timestamp in the file signature (reveals system clock)')
parser_signmsg.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_signmsg.set_defaults(func = sign_message)


parser_signfile = subparsers.add_parser('sign-file', 
    help = 'Sign file')
parser_signfile.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify master key to file messages with')
parser_signfile.add_argument('--file', 
    type = str,
    required = True,
    help = 'Specify file to sign')
parser_signfile.add_argument('--output',
    type = str,
    help = 'Specify output file for signature')
parser_signfile.add_argument('--timestamp', 
    action = 'store_true', 
    help = 'Include timestamp in the file signature (reveals system clock)')
parser_signfile.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_signfile.set_defaults(func = sign_file)


parser_verifymsg = subparsers.add_parser('verify-message', 
    help = 'Verify signed message')
parser_verifymsg.add_argument('--msg', 
    type = str,
    required = True,
    help = 'Specify text message file with signed message to verify')
parser_verifymsg.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_verifymsg.set_defaults(func = verify_message)


parser_verifyfile = subparsers.add_parser('verify-file',
    help = 'Verify signed file')
parser_verifyfile.add_argument('--file',
    type = str,
    required = True,
    help = 'Specify file to verify')
parser_verifyfile.add_argument('--signature',
    dest = 'sig',
    type = str,
    required = True,
    help = 'Specify file signature to verify')
parser_verifyfile.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_verifyfile.set_defaults(func = verify_file)


parser_genkey = subparsers.add_parser('gen-key',
    help = 'Generate new private key (Master key)')
parser_genkey.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_genkey.set_defaults(func = gen_masterkey)


parser_showmasterkeys = subparsers.add_parser('master-keys',
    help = 'Display all private keys (Master keys)')
parser_showmasterkeys.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_showmasterkeys.set_defaults(func = print_masterkeys)


parser_editmasterkey = subparsers.add_parser('set-key-alias',
    help = 'Set an alias for a given private key (Master key)')
parser_editmasterkey.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify private key (Master keys)')
parser_editmasterkey.add_argument('--alias',
    type = str,
    required = True,
    help = 'Specify alias string')
parser_editmasterkey.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_editmasterkey.set_defaults(func = edit_masterkeyalias)


parser_setkeypass = subparsers.add_parser('set-key-pass',
    help = 'Set or change password for private key (Master key)')
parser_setkeypass.add_argument('--master-key', 
    type = str,
    required = True,
    help = 'Specify private key (Master keys)')
parser_setkeypass.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_setkeypass.set_defaults(func = set_masterkey_pass)


parser_remkeypass = subparsers.add_parser('del-key-pass',
    help = 'Remove password from private key (Master key)')
parser_remkeypass.add_argument('--master-key', 
    type = str,
    required = True,
    help = 'Specify private key (Master keys)')
parser_remkeypass.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_remkeypass.set_defaults(func = remove_masterkey_pass)


parser_delkey = subparsers.add_parser('del-key',
    help = 'Delete one or more private keys (Master keys)')
parser_delkey.add_argument('--master-key',
    nargs = '+',
    dest = 'id',
    type = str,
    required = True,
    help = 'Specify one or more keys to delete')
parser_delkey.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_delkey.set_defaults(func = del_masterkey)


parser_addcontact = subparsers.add_parser('add-contact',
    help = 'Add contact public key to the key ring')
parser_addcontact.add_argument('--public-key',
    dest = 'pubkey',
    required = True,
    help = 'Public key to add to the key ring')
parser_addcontact.add_argument('--alias',
    type = str,
    help = 'Alias for added contact')
parser_addcontact.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_addcontact.set_defaults(func = add_contactkey)


parser_showcontacts = subparsers.add_parser('contacts',
    help = 'Display all contact keys')
parser_showcontacts.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_showcontacts.set_defaults(func = print_contacts)


parser_editcontact = subparsers.add_parser('set-contact-alias',
    help = 'Set an alias for a given contact key')
parser_editcontact.add_argument('--contact-id',
    type = str,
    required = True,
    help = 'Specify contact key')
parser_editcontact.add_argument('--alias',
    type = str,
    required = True,
    help = 'Specify alias string')
parser_editcontact.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_editcontact.set_defaults(func = edit_contactalias)


parser_delcontact = subparsers.add_parser('del-contact',
    help = 'Delete one or more contact keys')
parser_delcontact.add_argument('--contact-id',
    nargs = '+',
    dest = 'id',
    type = str,
    required = True,
    help = 'Specify one or more keys to delete')
parser_delcontact.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_delcontact.set_defaults(func = del_contactkey)




if len(sys.argv) < 2:
    while(True):
        try:
            a = raw_input('{} > '.format(os.path.basename(sys.argv[0])))
            args = arg_parser.parse_args(a.split())
            args.func(args)
        except SystemExit as e:
            pass
        except KeyboardInterrupt:
            sys.exit()
else:
    args = arg_parser.parse_args()
    args.func(args)

