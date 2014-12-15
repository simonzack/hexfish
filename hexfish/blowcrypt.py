
'''
mircrypt/blowcrypt/FiSH encryption
'''

import struct

from Crypto.Cipher import Blowfish

from .crypto import cbc_decrypt, cbc_encrypt, pad_to

__all__ = ['BlowCrypt', 'BlowCryptCBC']


class BlowCryptBase:
    @staticmethod
    def b64encode(s):
        '''
        Non-standard base64 with various bit & endian reversals.
        '''
        b64 = b'./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        res = bytearray()
        while s:
            left, right = struct.unpack('>LL', s[:8])
            for i in range(6):
                res.append(b64[right & 0x3f])
                right >>= 6
            for i in range(6):
                res.append(b64[left & 0x3f])
                left >>= 6
            s = s[8:]
        return bytes(res)

    @staticmethod
    def b64decode(s):
        b64 = b'./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        res = bytearray()
        while s:
            left, right = 0, 0
            for i, p in enumerate(s[0:6]):
                right |= b64.index(p) << (i * 6)
            for i, p in enumerate(s[6:12]):
                left |= b64.index(p) << (i * 6)
            res.extend(struct.pack('>LL', left, right))
            s = s[12:]
        return bytes(res)

    def encrypt(self, msg):
        raise NotImplementedError

    def decrypt(self, msg):
        raise NotImplementedError


class BlowCrypt(BlowCryptBase):
    def __init__(self, key=None):
        self.blowfish = Blowfish.new(key)

    def pack(self, msg):
        '''
        Get the irc string to send.
        '''
        return '+OK {}'.format(self.b64encode(self.encrypt(pad_to(msg.encode(), 8))).decode())

    def unpack(self, msg):
        if not (msg.startswith('+OK ') or msg.startswith('mcps ')):
            raise ValueError
        _, body = msg.split(' ', 1)
        if len(body) % 12 != 0:
            raise ValueError('msg')
        return self.decrypt(self.b64decode(body.encode())).strip(b'\x00').decode('utf-8', 'ignore')

    def encrypt(self, data):
        return self.blowfish.encrypt(data)

    def decrypt(self, data):
        return self.blowfish.decrypt(data)


class BlowCryptCBC(BlowCryptBase):
    def __init__(self, key=None):
        self.blowfish = Blowfish.new(key)

    def pack(self, msg):
        '''
        Get the irc string to send.
        '''
        return '+OK *{}'.format(self.b64encode(self.encrypt(pad_to(msg.encode(), 8))).decode())

    def unpack(self, msg):
        if not (msg.startswith('+OK *') or msg.startswith('mcps *')):
            raise ValueError
        _, body = msg.split(' *', 1)
        if len(body) % 12 != 0:
            raise ValueError('msg')
        return self.decrypt(self.b64decode(body.encode())).strip(b'\x00').decode('utf-8', 'ignore')

    def encrypt(self, data):
        return cbc_encrypt(self.blowfish.encrypt, data, 8)

    def decrypt(self, data):
        return cbc_decrypt(self.blowfish.decrypt, data, 8)


# XXX add a class to decide which class to use
