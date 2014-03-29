
'''
irc blowfish encoding/decoding
'''

import struct
from .crypto import cbc_encrypt, cbc_decrypt, blowfish, padto, MalformedError

class Blowfish:
    def __init__(self, key=None):
        if key:
            self.blowfish = blowfish.new(key)

    def decrypt(self, data):
        return self.blowfish.decrypt(data)

    def encrypt(self, data):
        return self.blowfish.encrypt(data)

class BlowfishCBC:
    def __init__(self, key=None):
        if key:
            self.blowfish = blowfish.new(key)

    def decrypt(self, data):
        return cbc_decrypt(self.blowfish.decrypt, data, 8)

    def encrypt(self, data):
        return cbc_encrypt(self.blowfish.encrypt, data, 8)

## blowcrypt, Fish etc.
def blowcrypt_b64encode(s):
    """A non-standard base64-encode."""
    b64 = b"./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = bytearray()
    while s:
        left, right = struct.unpack('>LL', s[:8])
        for i in range(6):
            res.append( b64[right & 0x3f] )
            right >>= 6
        for i in range(6):
            res.append( b64[left & 0x3f] )
            left >>= 6
        s = s[8:]
    return bytes(res)

def blowcrypt_b64decode(s):
    """A non-standard base64-decode."""
    b64 = b"./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = bytearray()
    while s:
        left, right = 0, 0
        for i, p in enumerate(s[0:6]):
            right |= b64.index(p) << (i * 6)
        for i, p in enumerate(s[6:12]):
            left |= b64.index(p) << (i * 6)
        res.extend( struct.pack('>LL', left, right) )
        s = s[12:]
    return bytes(res)

def blowcrypt_pack(msg, cipher):
    """
    Uses strings instead of bytes as these are intended to be human-readable in irc clients.
    """
    return '+OK %s' % (blowcrypt_b64encode(cipher.encrypt(padto(msg.encode(), 8))))

def blowcrypt_unpack(msg, cipher):
    """
    See blowcrypt_pack.
    """
    if not (msg.startswith('+OK ') or msg.startswith('mcps ')):
        raise ValueError
    _, rest = msg.split(' ', 1)
    if len(rest) % 12 != 0:
        raise MalformedError

    try:
        raw = blowcrypt_b64decode(rest.encode())
    except TypeError:
        raise MalformedError
    if not raw:
        raise MalformedError

    try:
        plain = cipher.decrypt(raw)
    except ValueError:
        raise MalformedError

    return plain.strip(b'\x00').decode('utf-8', 'ignore')
