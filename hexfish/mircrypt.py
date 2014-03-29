
'''
irc mircrypt encoding/decoding
'''

import base64
from .crypto import cbc_encrypt, cbc_decrypt, blowfish, padto

class MirCryptBase:
    def pack(self, msg, cipher):
        '''
        Get the irc string to send.
        '''
        padded = padto(msg.encode(), 8)
        return '+OK *{}'.format(base64.b64encode(cipher.encrypt(padded)).decode())

    def unpack(self, msg, cipher):
        """
        See mircryption_cbc_pack.
        """
        if not (msg.startswith('+OK *') or msg.startswith('mcps *')):
            raise ValueError
        _, body = msg.split(' *', 1)
        if len(body) % 12 != 0:
            raise ValueError('msg')
        return self.decrypt(base64.b64decode(body.encode())).strip(b'\x00').decode('utf-8', 'ignore')

    def encrypt(self, msg):
        raise NotImplementedError

    def decrypt(self, msg):
        raise NotImplementedError


class MirCrypt(MirCryptBase):
    def __init__(self, key=None):
        self.blowfish = blowfish.new(key)

    def decrypt(self, data):
        return self.blowfish.decrypt(data)

    def encrypt(self, data):
        return self.blowfish.encrypt(data)


class MirCryptCBC(MirCryptBase):
    def __init__(self, key=None):
        self.blowfish = blowfish.new(key)

    def decrypt(self, data):
        return cbc_decrypt(self.blowfish.decrypt, data, 8)

    def encrypt(self, data):
        return cbc_encrypt(self.blowfish.encrypt, data, 8)
