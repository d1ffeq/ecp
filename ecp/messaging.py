import binascii
import re
import time
import zlib
import keyfmt as KeyFormatting
import crypto as Crypto
import parsing as Parsing



p = Parsing.Parser()


class EncryptMessage(object):
    '''Main encryption class'''
    def __init__(self, their_id, your_id = None, keypass = None):
        self.timestamp = (time.strftime("%m%d%H%M%S"))    # Timestamp for filename
        if your_id:
            self.your_keypair = KeyFormatting.Key(key_id = your_id, passwd = keypass)    # Setting up a user key, providing password if needed
            self.your_private = self.your_keypair.get_priv('lib')    # Setting up user private key in "library" form
            self.your_public = self.your_keypair.get_pub('lib')    # Setting up users public key in "library" form
            self.your_public_short = self.your_keypair.get_pub('msg')    # Setting up users public key in "short" form

        self.eph_keypair = KeyFormatting.Key()    # Generating ephemeral keypair for ECDH
        self.eph_private = self.eph_keypair.get_priv('lib')    # Getting private part of ephemeral keypairin "library" form
        self.eph_public = self.eph_keypair.get_pub('lib')    # Getting public part of ephemeral keypair in "library" form
        self.eph_public_short = self.eph_keypair.get_pub('msg')    # Getting public part of ephemeral keypair in "short" form

        self.msg_token = Crypto.generate_token()    # Generating a message encryption token
        self.their_id = their_id    # Setting up a receivers ID object, which is a list for > 1 recepients or a string for 1


    def encrypt_normal(self, txt):
        '''Method to encrypt a regular message'''
        compress_txt = zlib.compress(txt)
        encrypted_txt = Crypto.encrypt(self.msg_token, compress_txt)
        encrypted_tokens = []
        hmac = Crypto.make_hmac(self.msg_token, encrypted_txt)
        for id in self.their_id:
            their_b58public = KeyFormatting.retrieve_contact_key(id)
            their_public = KeyFormatting.fmt_pub(their_b58public, 'readable2lib')
            secret = Crypto.ecdh_secret(self.eph_private, 
                                        self.eph_public,
                                        their_public)
            encrypt_tkn = Crypto.encrypt(secret, self.msg_token)
            encrypted_tokens.append(encrypt_tkn)
        msg = p.construct_normal(self.their_id,
                                encrypted_tokens,
                                self.eph_public_short,
                                self.your_public_short,
                                encrypted_txt,
                                hmac)
        signature = Crypto.make_sig(self.your_private, self.your_public, msg)
        msg += p.build_message_sig(signature)
        return msg, self.timestamp + '.msg'


    def encrypt_incognito(self, txt):
        '''Method to encrypt incognito message'''
        compress_txt = zlib.compress(txt)
        encrypted_txt = Crypto.encrypt(self.msg_token, compress_txt)
        encrypted_tokens = []
        hmac = Crypto.make_hmac(self.msg_token, encrypted_txt)
        for id in self.their_id:
            their_b58public = KeyFormatting.retrieve_contact_key(id)
            their_public = KeyFormatting.fmt_pub(their_b58public, 'readable2lib')
            secret = Crypto.ecdh_secret(self.eph_private, 
                                        self.eph_public, 
                                        their_public)
            encrypt_tkn = Crypto.encrypt(secret, self.msg_token)
            encrypted_tokens.append(encrypt_tkn)
        msg = p.construct_incognito(self.their_id, 
                                    encrypted_tokens,
                                    self.eph_public_short,
                                    encrypted_txt,
                                    hmac)
        signature = Crypto.make_sig(self.eph_private, self.eph_public, msg)
        msg += p.build_message_sig(signature)
        return msg, self.timestamp + '.msg' 


    def encrypt_obfuscated(self, payload):
        '''Method to encrypt obfuscated message'''
        encrypted_txt = Crypto.encrypt(self.msg_token, payload)
        encrypted_tokens = []
        hmac = Crypto.make_hmac(self.msg_token, encrypted_txt)
        for id in self.their_id:
            their_b58public = KeyFormatting.retrieve_contact_key(id)
            their_public = KeyFormatting.fmt_pub(their_b58public, 'readable2lib')
            secret = Crypto.ecdh_secret(self.eph_private, 
                                        self.eph_public,  
                                        their_public)
            encrypt_tkn = Crypto.encrypt(secret, self.msg_token)
            encrypted_tokens.append(encrypt_tkn)
        msg = p.construct_obfuscated(encrypted_tokens,
                                    self.eph_public_short,
                                    encrypted_txt,
                                    hmac)
        signature = Crypto.make_sig(self.eph_private, self.eph_public, msg)
        msg += p.build_message_sig(signature)
        return msg, self.timestamp + '.msg' 




class DecryptException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


class DecryptMessage(object):
    '''Main decryption class'''
    def __init__(self, your_id = None, keypass = None):
        if your_id:
            self.your_id = your_id    # Setting up user ID object
            self.your_keypair = KeyFormatting.Key(key_id = your_id, passwd = keypass)    # Setting up a user key, providing password if needed
            self.your_private = self.your_keypair.get_priv('lib')    # Setting up user private key in "library" form
            self.your_public = self.your_keypair.get_pub('lib')    # Setting up users public key in "library" form
            self.your_public_short = self.your_keypair.get_pub('msg')    # Setting up users public key in "short" form


    def decrypt_normal(self, message):
        '''Method to decrypt normal message'''
        data, fullmsg = p.deconstruct_normal(message)
        their_public = KeyFormatting.fmt_pub(fullmsg.sender_public, 'msg2lib')
        if Crypto.verify_sig(their_public, fullmsg.signature, data) is True:
            their_public_raw = KeyFormatting.fmt_pub(fullmsg.sender_public, 'msg2raw')
            their_id = KeyFormatting.form_key_id(their_public_raw)
            eph_public = KeyFormatting.fmt_pub(fullmsg.eph_key, 'msg2lib')
            your_posit = fullmsg.recipient_ids.index(self.your_id) 
            encrypted_tkn = fullmsg.token_list[your_posit]
            secret = Crypto.ecdh_secret(self.your_private, 
                                        self.your_public, 
                                        eph_public)
            decrypted_tkn = Crypto.decrypt(secret, encrypted_tkn)
            if fullmsg.msg_hmac == Crypto.make_hmac(decrypted_tkn, fullmsg.ciphertext):
                compressed_txt = Crypto.decrypt(decrypted_tkn, fullmsg.ciphertext)
                plaintext = zlib.decompress(compressed_txt)
                status = 'Decrypted message from {}'.format(their_id)
                msg_info = self.form_msg_info(their_id, fullmsg.recipient_ids, plaintext, fullmsg)
                return plaintext, status, msg_info
            else:
                raise DecryptException('Corrupted message - HMAC failure!')
        else:
            raise DecryptException('Corrupted message - signature failure!')


    def decrypt_incognito(self, message):
        '''Method to decrypt incognito message'''
        data, fullmsg = p.deconstruct_incognito(message)
        eph_public = KeyFormatting.fmt_pub(fullmsg.eph_key, 'msg2lib')
        if Crypto.verify_sig(eph_public, fullmsg.signature, data) is True:
            your_posit = fullmsg.recipient_ids.index(self.your_id) 
            encrypted_tkn = fullmsg.token_list[your_posit]
            secret = Crypto.ecdh_secret(self.your_private, 
                                        self.your_public, 
                                        eph_public)
            decrypted_tkn = Crypto.decrypt(secret, encrypted_tkn)
            if fullmsg.msg_hmac == Crypto.make_hmac(decrypted_tkn, fullmsg.ciphertext):
                compressed_txt = Crypto.decrypt(decrypted_tkn, fullmsg.ciphertext)
                plaintext = zlib.decompress(compressed_txt)
                status = 'Decrypted message from Incognito sender '
                msg_info = self.form_msg_info('Incognito', fullmsg.recipient_ids, plaintext, fullmsg)
                return plaintext, status, msg_info
            else:
                raise DecryptException('Corrupted message - HMAC failure!')
        else:
            raise DecryptException('Corrupted message - signature failure!')


    def decrypt_obfuscated(self, message):
        '''Method to decrypt obfuscated message'''
        data, fullmsg = p.deconstruct_obfuscated(message)
        eph_public = KeyFormatting.fmt_pub(fullmsg.eph_key, 'msg2lib')
        if Crypto.verify_sig(eph_public, fullmsg.signature, data) is True:
            for enc_token in fullmsg.token_list:
                secret = Crypto.ecdh_secret(self.your_private, 
                                            self.your_public, 
                                            eph_public)
                try:
                    decrypted_tkn = Crypto.decrypt(secret, enc_token)
                    if fullmsg.msg_hmac == Crypto.make_hmac(decrypted_tkn, fullmsg.payload):
                        return Crypto.decrypt(decrypted_tkn, fullmsg.payload)
                except Exception:
                    pass
            return None
        else:
            raise DecryptException('Corrupted message - signature failure!')



    def form_msg_info(self, their_id, id_list, text, fullmsg):
        '''Method to form information about decrypted message'''
        contact_known = KeyFormatting.check_contact_identity(their_id)
        if contact_known is True and their_id is not 'Incognito':
            their_alias = KeyFormatting.retrieve_contact_alias(their_id)
            notice = ''
        elif contact_known is False and their_id is not 'Incognito':
            their_alias = ''
            their_b58public = KeyFormatting.fmt_pub(fullmsg.sender_public, 'msg2readable')
            notice = u'Unknown key: {}'.format(their_b58public)
        elif their_id is 'Incognito':
            their_alias = ''
            notice = ''
        s = u'Message from:     {} {}'.format(their_id, their_alias) + '\n'
        s += u'Decrypted with:   {}'.format(self.your_id) + '\n'
        s += u'Message for:      {}'.format(', '.join(id_list)) + '\n'
        s += u'Text length:      {} byte(s)'.format(len(bytes(text))) + '\n'
        s += notice
        return s




class SignData(object):
    '''Main signing class'''
    def __init__(self, your_id = None, keypass = None):
        if your_id:
            self.your_id = your_id    # Setting up user ID object
            self.your_keypair = KeyFormatting.Key(key_id = your_id, passwd = keypass)    # Setting up a user key, providing password if needed
            self.your_private = self.your_keypair.get_priv('lib')    # Setting up user private key in "library" form
            self.your_public = self.your_keypair.get_pub('lib')    # Setting up users public key in "library" form
            self.your_public_short = self.your_keypair.get_pub('msg')    # Setting up users public key in "short" form
        self.timestamp = int(time.time())


    def sign_clearsign(self, text):
        '''Method to sign a clearsign text'''
        sig_metadata = p.construct_clearsigned(self.your_public_short)
        data_to_sign = text + sig_metadata
        signature = Crypto.make_sig(self.your_private, self.your_public, data_to_sign)
        signature_string = p.build_message_sig(signature)
        fullsig = sig_metadata + signature_string
        signed_text = msg_signature_encode(text, fullsig)
        return signed_text


    def sign_clearsign_t(self, text):
        '''Method to sign a clearsign text with timestamp'''
        sig_metadata = p.construct_clearsigned_t(self.your_public_short, self.timestamp)
        data_to_sign = text + sig_metadata
        signature = Crypto.make_sig(self.your_private, self.your_public, data_to_sign)
        signature_string = p.build_message_sig(signature)
        fullsig = sig_metadata + signature_string
        signed_text = msg_signature_encode(text, fullsig)
        return signed_text


    def sign_detached(self, data):
        '''Method to sign a file-detached signature'''
        sig_metadata = p.construct_detached(self.your_public_short)
        data_to_sign = data + sig_metadata
        signature = Crypto.make_sig(self.your_private, self.your_public, data_to_sign)
        signature_string = p.build_message_sig(signature)
        fullsig = sig_metadata + signature_string
        encoded_sig = file_signature_encode(fullsig)
        return encoded_sig


    def sign_detached_t(self, data):
        '''Method to sign a file-detached signature'''
        sig_metadata = p.construct_detached_t(self.your_public_short, self.timestamp)
        data_to_sign = data + sig_metadata
        signature = Crypto.make_sig(self.your_private, self.your_public, data_to_sign)
        signature_string = p.build_message_sig(signature)
        fullsig = sig_metadata + signature_string
        encoded_sig = file_signature_encode(fullsig)
        return encoded_sig




class VerificationException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


class VerifySignature(object):
    '''Main signature verification class'''
    def __init__(self):
        pass


    def verify_clearsigned(self, data, sig):
        '''Method to verify clearsign texr signature'''
        sig_metadata, fullsig = p.deconstruct_clearsigned(sig)
        their_public_raw = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2raw')
        their_id = KeyFormatting.form_key_id(their_public_raw)
        their_public = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2lib')
        data_to_verify = data + sig_metadata
        if Crypto.verify_sig(their_public, fullsig.signature, data_to_verify) is True:
            sig_info = self.form_sig_info(their_id, fullsig.signee_public, data)
            status = 'Good message signature from: ' + their_id
            return status, sig_info
        else:
            raise VerificationException('Corrupted message - signature failure!')


    def verify_clearsigned_t(self, data, sig):
        '''Method to verify clearsign text signature with timestamp'''
        sig_metadata, fullsig = p.deconstruct_clearsigned_t(sig)
        time_readable = time.ctime(fullsig.timestamp)
        their_public_raw = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2raw')
        their_id = KeyFormatting.form_key_id(their_public_raw)
        their_public = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2lib')
        data_to_verify = data + sig_metadata
        if Crypto.verify_sig(their_public, fullsig.signature, data_to_verify) is True:
            sig_info = self.form_sig_info(their_id, fullsig.signee_public, data, time_readable)
            status = 'Good message signature from: ' + their_id
            return status, sig_info
        else:
            raise VerificationException('Corrupted message - signature failure!')



    def verify_detached(self, data, sig):
        '''Method to verify detached file signature'''
        sig_metadata, fullsig = p.deconstruct_detached(sig)
        their_public_raw = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2raw')
        their_id = KeyFormatting.form_key_id(their_public_raw)
        their_public = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2lib')
        data_to_verify = data + sig_metadata
        if Crypto.verify_sig(their_public, fullsig.signature, data_to_verify) is True:
            sig_info = self.form_sig_info(their_id, fullsig.signee_public, data)
            status = 'Good file signature from: ' + their_id
            return status, sig_info
        else:
            raise VerificationException('Corrupted message - signature failure!')


    def verify_detached_t(self, data, sig):
        '''Method to verify detached file signature with timestamp'''
        sig_metadata, fullsig = p.deconstruct_detached_t(sig)
        time_readable = time.ctime(fullsig.timestamp)
        their_public_raw = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2raw')
        their_id = KeyFormatting.form_key_id(their_public_raw)
        their_public = KeyFormatting.fmt_pub(fullsig.signee_public, 'msg2lib')
        data_to_verify = data + sig_metadata
        if Crypto.verify_sig(their_public, fullsig.signature, data_to_verify) is True:
            sig_info = self.form_sig_info(their_id, fullsig.signee_public, data, time_readable)
            status = 'Good file signature from: ' + their_id
            return status, sig_info
        else:
            raise VerificationException('Corrupted message - signature failure!')


    def form_sig_info(self, their_id, their_public, data, timestamp = None):
        '''Method to form information about verified signature and data'''
        their_public_readable = KeyFormatting.fmt_pub(their_public, 'msg2readable')
        contact_known = KeyFormatting.check_contact_identity(their_id)
        if contact_known is True:
            their_alias = KeyFormatting.retrieve_contact_alias(their_id)
        elif contact_known is False:
            their_alias = ''
        s = u'Signed by:  {} {}'.format(their_id, their_alias) + '\n'
        s += u'Public key: {}'.format(their_public_readable) + '\n'
        s += u'Data size:  {} byte(s)'.format(len(bytes(data))) + '\n'
        if timestamp:
            s += u'Signed on:  {}'.format(timestamp) + '\n'
        return s




class DecodeException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


def message_encode(bin_msg):
    '''MIME-encodes (a.k.a. ASCII armors) encrypted message'''
    s = '-----BEGIN ECP MESSAGE-----\n' 
    s += ascii_armor(bin_msg)
    s += '-----END ECP MESSAGE-----'
    return s


def message_decode(mime_msg):
    '''Decodes encrypted message with regexp
    
    Raises decode error in case of failure'''
    begin_header = r'-----BEGIN ECP MESSAGE-----'
    b64_encoding = r'([A-Za-z0-9+/=\n\s]+)'
    end_header = r'-----END ECP MESSAGE-----'
    reg = re.compile(begin_header + b64_encoding + end_header, re.DOTALL|re.M)
    tag_match = reg.search(mime_msg)
    if tag_match:
        b64msg = (tag_match.group(1).strip())
    elif not tag_match:
        raise DecodeException('Corrupted/invalid message - parsing failure!')
    try:
        message = binascii.a2b_base64(b64msg)
    except binascii.Error: 
        raise DecodeException('Corrupted/invalid message - decoding failure!')
    return message


def msg_signature_encode(text, sig):
    '''MIME-encodes text signaute'''
    s = u'-----BEGIN ECP SIGNED MESSAGE-----\n'
    s += text.decode('utf-8')
    s += u'\n-----BEGIN ECP SIGNATURE-----\n'
    s += ascii_armor(sig)
    s += u'-----END ECP SIGNATURE-----'
    return s


def msg_signature_decode(msg):
    '''Decodes signature with regexp
    
    Raises decode error in case of failure'''
    begin_header = r'-----BEGIN ECP SIGNED MESSAGE-----'
    get_txt = r'(.*)'
    end_header = r'-----BEGIN ECP SIGNATURE-----'
    reg1 = re.compile(begin_header + get_txt + end_header, re.DOTALL)
    text_tag_match = reg1.search(msg)
    if text_tag_match:
        h_text = (text_tag_match.group(0).strip())
        text = h_text[len(begin_header + '\n'):-len(end_header + '\n')]
    elif not text_tag_match:
        raise DecodeException('Corrupted/invalid signature - parsing failure!')
    begin_header = r'-----BEGIN ECP SIGNATURE-----'
    b64_encoding = r'([A-Za-z0-9+/=\n\s]+)'
    end_header = r'-----END ECP SIGNATURE-----'
    reg2 = re.compile(begin_header + b64_encoding + end_header, re.DOTALL|re.M)
    b64_tag_match = reg2.search(msg)
    if b64_tag_match:
        b64_sig = (b64_tag_match.group(1).strip())
    elif not b64_tag_match:
        raise DecodeException('Corrupted/invalid signature - parsing failure!')
    try:
        signature = binascii.a2b_base64(b64_sig)
    except binascii.Error: 
        raise DecodeException('Corrupted/invalid signature - decoding failure!')
    return text, signature


def file_signature_encode(sig):
    '''MIME-encodes a detached signature'''
    s = u'-----BEGIN ECP FILE SIGNATURE-----\n'
    s += ascii_armor(sig)
    s += u'-----END ECP FILE SIGNATURE-----'
    return s


def file_signature_decode(mime_sig):
    '''Decodes detached file signature
    
    Raises decode error in case of failure'''
    begin_header = r'-----BEGIN ECP FILE SIGNATURE-----'
    b64_encoding = r'([A-Za-z0-9+/=\n\s]+)'
    end_header = r'-----END ECP FILE SIGNATURE-----'
    reg = re.compile(begin_header + b64_encoding + end_header, re.DOTALL|re.M)
    tag_match = reg.search(mime_sig)
    if tag_match:
        b64msg = (tag_match.group(1).strip())
    elif not tag_match:
        raise DecodeException('Corrupted/invalid signature - parsing failure!')
    try:
        sig = binascii.a2b_base64(b64msg)
    except binascii.Error: 
        raise DecodeException('Corrupted/invalid signature - decoding failure!')
    return sig


def ascii_armor(s):
    '''Base64 encoding with 64-char width'''
    line_length = 64
    binsize = (line_length // 4) * 3
    pieces = []
    for i in range(0, len(s), binsize):
        chunk = s[i : i + binsize]
        pieces.append(binascii.b2a_base64(chunk))
    return "".join(pieces)


def get_message_type(message):
    '''Translates magic number of message type into a human-readable form'''
    msg_type = ord(message[0:1])
    if msg_type is 12:
        return 'normal'
    elif msg_type is 24:
        return 'incognito'
    elif msg_type is 36:
        return 'obfuscated'
    else:
        return 'unknown'


def get_signature_type(sig):
    '''Translates magic number of signature type into a human-readable form'''
    type = ord(sig[0:1])
    if type is 7:
        return 'clearsign'
    elif type is 14:
        return 'clearsign_t'
    elif type is 21:
        return 'detached'
    elif type is 28:
        return 'detached_t'
    else:
        return 'unkonwn'

