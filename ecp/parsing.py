from construct import *
import ConfigParser




class ParserException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


class Parser:
    def __init__(self):

        '''Message structures that define message types. '''

        '''Signature string. '''
        self.sig = PascalString('signature', length_field = UBInt8('length'))

        '''Type 12 message. Identified, without attachment'''
        self.NormalTypePresigned = Struct('msg',
                                        UBInt8('type'),
                                        UBInt8('recipient_num'),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('recipient_ids', length_field = UBInt8('length'))),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('token_list', length_field = UBInt8('length'))),
                                        PascalString('eph_key', length_field = UBInt8('length')),
                                        PascalString('sender_public', length_field = UBInt8('length')),
                                        PascalString('ciphertext', length_field = UBInt32('length')),
                                        PascalString('msg_hmac', length_field = UBInt8('length')), )


        self.NormalTypeSigned = Struct('msg',
                                        UBInt8('type'),
                                        UBInt8('recipient_num'),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('recipient_ids', length_field = UBInt8('length'))),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('token_list', length_field = UBInt8('length'))), 
                                        PascalString('eph_key', length_field = UBInt8('length')),
                                        PascalString('sender_public', length_field = UBInt8('length')),
                                        PascalString('ciphertext', length_field = UBInt32('length')),
                                        PascalString('msg_hmac', length_field = UBInt8('length')),
                                        PascalString('signature', length_field = UBInt8('length')), )

        '''Type 24 message, unidentified (incognito) without attachment'''
        self.IncognitoTypePresigned = Struct('msg',
                                        UBInt8('type'),
                                        UBInt8('recipient_num'),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('recipient_ids', length_field = UBInt8('length'))),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('token_list', length_field = UBInt8('length'))), 
                                        PascalString('eph_key', length_field = UBInt8('length')),
                                        PascalString('ciphertext', length_field = UBInt32('length')),
                                        PascalString('msg_hmac', length_field = UBInt8('length')), )
        self.IncognitoTypeSigned = Struct('msg',
                                        UBInt8('type'),
                                        UBInt8('recipient_num'),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('recipient_ids', length_field = UBInt8('length'))),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('token_list', length_field = UBInt8('length'))), 
                                        PascalString('eph_key', length_field = UBInt8('length')),
                                        PascalString('ciphertext', length_field = UBInt32('length')),
                                        PascalString('msg_hmac', length_field = UBInt8('length')),
                                        PascalString('signature', length_field = UBInt8('length')), )

        '''Type 36 message. Hides all other message types inside'''
        self.ObfuscatedTypePresigned = Struct('msg',
                                        UBInt8('type'),
                                        UBInt8('recipient_num'),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('token_list', length_field = UBInt8('length'))), 
                                        PascalString('eph_key', length_field = UBInt8('length')),
                                        PascalString('payload', length_field = UBInt32('length')),
                                        PascalString('msg_hmac', length_field = UBInt8('length')), )
        self.ObfuscatedTypeSigned = Struct('msg',
                                        UBInt8('type'),
                                        UBInt8('recipient_num'),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('token_list', length_field = UBInt8('length'))), 
                                        PascalString('eph_key', length_field = UBInt8('length')),
                                        PascalString('payload', length_field = UBInt32('length')),
                                        PascalString('msg_hmac', length_field = UBInt8('length')),
                                        PascalString('signature', length_field = UBInt8('length')), )

        '''Structure for getting receivers list'''
        self.id_list_struct = Struct('anytype',
                                        UBInt8('type'),
                                        UBInt8('recipient_num'),
                                        Array(lambda ctx: ctx.recipient_num, 
                                            PascalString('recipient_ids', length_field = UBInt8('length'))), )

# ============================================================================================================

        '''Signature type 7, signed text message with no timestamp'''
        self.ClearsignSigPresigned = Struct('pre-signed', 
                                            UBInt8('type'),
                                            PascalString('signee_public', length_field = UBInt8('length')), )
        self.ClearsignSigSigned = Struct('msg', 
                                            UBInt8('type'),
                                            PascalString('signee_public', length_field = UBInt8('length')), 
                                            PascalString('signature', length_field = UBInt8('length')), )

        '''Signature type 14, signed text message with timestamp'''
        self.ClearsignSigTimedPresigned = Struct('pre-signed', 
                                            UBInt8('type'),
                                            UBInt32('timestamp'),
                                            PascalString('signee_public', length_field = UBInt8('length')), )
        self.ClearsignSigTimedSigned = Struct('msg', 
                                            UBInt8('type'),
                                            UBInt32('timestamp'),
                                            PascalString('signee_public', length_field = UBInt8('length')), 
                                            PascalString('signature', length_field = UBInt8('length')), )

        '''Signature type 21, signed file with no timestamp'''
        self.DetachedSigPresigned = Struct('pre-signed', 
                                            UBInt8('type'),
                                            PascalString('signee_public', length_field = UBInt8('length')), )
        self.DetachedSigSigned = Struct('msg', 
                                            UBInt8('type'),
                                            PascalString('signee_public', length_field = UBInt8('length')), 
                                            PascalString('signature', length_field = UBInt8('length')), )

        '''Signature type 28, signed file with timestamp'''
        self.DetachedSigTimedPresigned = Struct('pre-signed', 
                                            UBInt8('type'),
                                            UBInt32('timestamp'),
                                            PascalString('signee_public', length_field = UBInt8('length')), )
        self.DetachedSigTimedSigned = Struct('msg', 
                                            UBInt8('type'),
                                            UBInt32('timestamp'),
                                            PascalString('signee_public', length_field = UBInt8('length')), 
                                            PascalString('signature', length_field = UBInt8('length')), )


    def parse_rec_list(self, message):
        try:
            msg = self.id_list_struct.parse(message)
            return msg.recipient_ids
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')


    def build_message_sig(self, signature):
        return self.sig.build(signature)


    '''Message construction functions '''

    def construct_normal(self, their_ids, tkn_list, eph_public, sender_public, ciphertext, hmac):
        return self.NormalTypePresigned.build(Container(type = 12, 
                                                        recipient_num = len(their_ids),
                                                        recipient_ids = their_ids, 
                                                        token_list = tkn_list,
                                                        eph_key = eph_public, 
                                                        sender_public = sender_public,
                                                        ciphertext = ciphertext,
                                                        msg_hmac = hmac))


    def construct_incognito(self, their_ids, tkn_list, eph_public, ciphertext, hmac):
        return self.IncognitoTypePresigned.build(Container(type = 24,
                                                            recipient_num = len(their_ids),
                                                            recipient_ids = their_ids, 
                                                            token_list = tkn_list,
                                                            eph_key = eph_public, 
                                                            ciphertext = ciphertext,
                                                            msg_hmac = hmac))


    def construct_obfuscated(self, tkn_list, eph_public, payload_msg, hmac):
        return self.ObfuscatedTypePresigned.build(Container(type = 36,
                                                            recipient_num = len(tkn_list),
                                                            token_list = tkn_list,
                                                            eph_key = eph_public,
                                                            payload = payload_msg,
                                                            msg_hmac = hmac))



    '''Message deconstruction functions'''

    def deconstruct_normal(self, message):
        try:
            msg = self.NormalTypeSigned.parse(message)
            msg_to_verify = self.NormalTypePresigned.build(Container(type = 12,
                                                                    recipient_num = msg.recipient_num,
                                                                    recipient_ids = msg.recipient_ids,
                                                                    token_list = msg.token_list,
                                                                    eph_key = msg.eph_key,
                                                                    sender_public = msg.sender_public,
                                                                    ciphertext = msg.ciphertext,
                                                                    msg_hmac = msg.msg_hmac))
            return msg_to_verify, msg 
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')


    def deconstruct_incognito(self, message):
        try:
            msg = self.IncognitoTypeSigned.parse(message)
            msg_to_verify = self.IncognitoTypePresigned.build(Container(type = 24,
                                                                    recipient_num = msg.recipient_num,
                                                                    recipient_ids = msg.recipient_ids,
                                                                    token_list = msg.token_list,
                                                                    eph_key = msg.eph_key,
                                                                    ciphertext = msg.ciphertext,
                                                                    msg_hmac = msg.msg_hmac))
            return msg_to_verify, msg
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')


    def deconstruct_obfuscated(self, message):
        try:
            msg = self.ObfuscatedTypeSigned.parse(message)
            msg_to_verify = self.ObfuscatedTypePresigned.build(Container(type = 36,
                                                                    recipient_num = msg.recipient_num,
                                                                    token_list = msg.token_list,
                                                                    eph_key = msg.eph_key,
                                                                    payload = msg.payload,
                                                                    msg_hmac = msg.msg_hmac))
            return msg_to_verify, msg
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')


    '''Signature construction functions'''

    def construct_clearsigned(self, signee_public):
        sig_md = self.ClearsignSigPresigned.build(Container(type = 7,
                                                            signee_public = signee_public))
        return sig_md


    def construct_clearsigned_t(self, signee_public, time):
        sig_md = self.ClearsignSigTimedPresigned.build(Container(type = 14,
                                                                timestamp = time,
                                                                signee_public = signee_public))
        return sig_md


    def construct_detached(self, signee_public):
        sig_md = self.DetachedSigPresigned.build(Container(type = 21,
                                                            signee_public = signee_public))
        return sig_md


    def construct_detached_t(self, signee_public, time):
        sig_md = self.DetachedSigTimedPresigned.build(Container(type = 28,
                                                                timestamp = time,
                                                                signee_public = signee_public))
        return sig_md



    '''Signature deconstruction functions'''

    def deconstruct_clearsigned(self, signature_block):
        try:
            sig = self.ClearsignSigSigned.parse(signature_block)
            sig_to_verify = self.ClearsignSigPresigned.build(Container(type = sig.type,
                                                                signee_public = sig.signee_public))
            return sig_to_verify, sig
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')


    def deconstruct_clearsigned_t(self, signature_block):
        try:
            sig = self.ClearsignSigTimedSigned.parse(signature_block)
            sig_to_verify = self.ClearsignSigTimedPresigned.build(Container(type = sig.type,
                                                                timestamp = sig.timestamp,
                                                                signee_public = sig.signee_public))
            return sig_to_verify, sig
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')


    def deconstruct_detached(self, signature_block):
        try:
            sig = self.DetachedSigSigned.parse(signature_block)
            sig_to_verify = self.DetachedSigPresigned.build(Container(type = sig.type,
                                                                signee_public = sig.signee_public))
            return sig_to_verify, sig
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')


    def deconstruct_detached_t(self, signature_block):
        try:
            sig = self.DetachedSigTimedSigned.parse(signature_block)
            sig_to_verify = self.DetachedSigTimedPresigned.build(Container(type = sig.type,
                                                                timestamp = sig.timestamp,
                                                                signee_public = sig.signee_public))
            return sig_to_verify, sig
        except (FieldError, AttributeError, OverflowError):
            raise ParserException('Corrupted message - parsing failure!')




class UnicodeConfigParser(ConfigParser.RawConfigParser):
    def __init__(self, *args, **kwargs):
        ConfigParser.RawConfigParser.__init__(self, *args, **kwargs)
 
    def write(self, fp):
        """Fixed for Unicode output"""
        if self._defaults:
            fp.write("[%s]\n" % DEFAULTSECT)
            for (key, value) in self._defaults.items():
                fp.write("%s = %s\n" % (key, unicode(value).replace('\n', '\n\t')))
            fp.write("\n")
        for section in self._sections:
            fp.write("[%s]\n" % section)
            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    fp.write("%s = %s\n" %
                             (key, unicode(value).replace('\n','\n\t')))
            fp.write("\n")
 
    # This function is needed to override default lower-case conversion
    # of the parameter's names. They will be saved 'as is'.
    def optionxform(self, strOut):
        return strOut

