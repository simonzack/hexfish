'''
mircrypt/blowcrypt/FiSH encryption
'''

import base64
import struct

from Crypto.Cipher import Blowfish
from hexfish.crypto import cbc_decrypt, cbc_encrypt, pad_to

__all__ = ['BlowCrypt', 'BlowCryptCBC', 'find_msg_cls']


class BlowCryptBase:
    send_prefix = ''
    receive_prefixes = []
    b64_alphabet = b'./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def __init__(self, key=None):
        if not 8 <= len(key) <= 56:
            raise ValueError('8 <= len(key) <= 56')
        self.blowfish = Blowfish.new(key.encode(), Blowfish.MODE_ECB)

    @classmethod
    def b64encode(cls, s):
        raise NotImplementedError

    @classmethod
    def b64decode(cls, s, partial=False):
        raise NotImplementedError

    def pack(self, msg):
        '''
        Get the irc string to send.
        '''
        return '{}{}'.format(self.send_prefix, self.b64encode(self.encrypt(pad_to(msg.encode(), 8))).decode())

    def unpack(self, msg, partial=False):
        try:
            prefix = next(prefix for prefix in self.receive_prefixes if msg.startswith(prefix))
        except StopIteration:
            raise ValueError
        body = msg[len(prefix):]
        return self.decrypt(self.b64decode(body.encode(), partial)).strip(b'\x00').decode('utf-8', 'ignore')

    def encrypt(self, msg):
        raise NotImplementedError

    def decrypt(self, msg):
        raise NotImplementedError


class BlowCrypt(BlowCryptBase):
    send_prefix = '+OK '
    receive_prefixes = ['+OK ', 'mcps ']

    @classmethod
    def b64encode(cls, s):
        '''
        Non-standard base64 with various bit & endian reversals.
        '''
        res = bytearray()
        if len(s) % 8 != 0:
            raise ValueError
        for i in range(0, len(s), 8):
            left, right = struct.unpack('>LL', s[i:i+8])
            for j in range(6):
                res.append(cls.b64_alphabet[right & 0x3f])
                right >>= 6
            for j in range(6):
                res.append(cls.b64_alphabet[left & 0x3f])
                left >>= 6
        return bytes(res)

    @classmethod
    def b64decode(cls, s, partial=False):
        res = bytearray()
        if not partial and len(s) % 12 != 0:
            raise ValueError
        try:
            for i in range(0, len(s)//12*12, 12):
                left, right = 0, 0
                for j, p in enumerate(s[i:i+6]):
                    right |= cls.b64_alphabet.index(p) << (j * 6)
                for j, p in enumerate(s[i+6:i+12]):
                    left |= cls.b64_alphabet.index(p) << (j * 6)
                res.extend(struct.pack('>LL', left, right))
        except ValueError:
            if not partial:
                raise
        return bytes(res)

    def encrypt(self, data):
        return self.blowfish.encrypt(data)

    def decrypt(self, data):
        return self.blowfish.decrypt(data)


class BlowCryptCBC(BlowCryptBase):
    send_prefix = '+OK *'
    receive_prefixes = ['+OK *', 'mcps *']

    @classmethod
    def b64encode(cls, s):
        if len(s) % 8 != 0:
            raise ValueError
        return base64.b64encode(s)

    @classmethod
    def b64decode(cls, s, partial=False):
        return base64.b64decode(s, validate=True)

    def encrypt(self, data):
        return cbc_encrypt(self.blowfish.encrypt, data, 8)

    def decrypt(self, data):
        return cbc_decrypt(self.blowfish.decrypt, data, 8)


def find_msg_cls(msg):
    # BlowCryptCBC has precedence since it's prefixes contain the prefixes of BlowCrypt
    for cls in (BlowCryptCBC, BlowCrypt):
        if any(msg.startswith(prefix) for prefix in cls.receive_prefixes):
            return cls
    raise ValueError('msg')
