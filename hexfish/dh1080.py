
'''
irc blowfish dh-1080 encoding/decoding
'''

import base64
import os
import hashlib
from .crypto import int_to_bytes, bytes_to_int

class DH1080:
    g = 2
    p = int(
        'FBE1022E23D213E8ACFA9AE8B9DFAD'
        'A3EA6B7AC7A7B7E95AB5EB2DF85892'
        '1FEADE95E6AC7BE7DE6ADBAB8A783E'
        '7AF7A7FA6A2B7BEB1E72EAE2B72F9F'
        'A2BFB2A2EFBEFAC868BADB3E828FA8'
        'BADFADA3E4CC1BE7E8AFE85E9698A7'
        '83EB68FA07A77AB6AD7BEB618ACF9C'
        'A2897EB28A6189EFA07AB99A8A7FA9'
        'AE299EFA7BA66DEAFEFBEFBF0B7D8B',
        16
    )
    q = (p - 1) // 2

    def __init__(self):
        self.public = 0
        self.private = 0
        self.secret = 0
        # 0: private key initialized, 1: sent request, 2: received request, 3: finished
        self.stage = 0
        self.cbc = None
        g, p, q = self.g, self.p, self.q
        bits = 1080
        while True:
            self.private = bytes_to_int(os.urandom(bits//8))
            self.public = pow(g, self.private, p)
            if self.validate_public_key(self.public) and self.validate_public_key_strict(self.public):
                break

    @staticmethod
    def b64encode(s):
        '''
        utf-7 base64 encode without padding characters, padding instead with 0 bits
        '''
        res = base64.b64encode(s)
        if b'=' in res:
            return res.rstrip(b'=')
        else:
            return res + b'='

    @staticmethod
    def b64decode(s):
        '''
        utf-7 base64 encode without padding characters, padding instead with 0 bits
        '''
        # remove trailing 'A' if it's just for padding
        if len(s)%4==1:
            s = s[:-1]
        # add padding characters
        s += b'='*((-len(s))%4)
        return base64.b64decode(s)

    def validate_public_key(self, public_key):
        return 1 < public_key < self.p

    def validate_public_key_strict(self, public_key):
        '''
        See RFC 2631 section 2.1.5.
        '''
        return pow(public_key, self.q, self.p) == 1

    def pack(self, cmd, key, cbc):
        res = '{} {}'.format(cmd, self.b64encode(int_to_bytes(key)))
        if cbc:
            res += ' CBC'
        return res

    def unpack(self, msg):
        words = msg.split()
        if len(words) not in (2, 3):
            raise ValueError('msg')
        cbc = False
        if len(words) == 3:
            if words[-1] == 'CBC':
                cbc = True
        cmd = words[0]
        if cmd not in ('DH1080_INIT', 'DH1080_FINISH'):
            raise ValueError('msg')
        key = self.b64decode(bytes_to_int(msg[1]))
        return cmd, key, cbc

    def send_request(self, cbc):
        if self.stage != 0:
            raise ValueError('stage')
        self.cbc = cbc
        self.stage = 1
        return self.pack('DH1080_INIT', self.public, cbc)

    def send_response(self):
        if self.stage != 2:
            raise ValueError('stage')
        self.stage = 3
        return self.pack('DH1080_FINISH', self.public, self.cbc)

    def receive_any(self, msg):
        cmd, cbc, public_key = self.unpack(msg)
        if cbc != self.cbc:
            raise ValueError('cbc request received a non-cbc response')
        if cmd == 'DH1080_INIT':
            if self.stage != 0:
                raise ValueError('stage')
        elif cmd == 'DH1080_FINISH':
            if self.stage != 1:
                raise ValueError('stage')
        if not self.validate_public_key(public_key):
            raise ValueError('invalid public key')
        invalid_strict_msg = 'Key does not conform to RFC 2631. This check is not performed by any DH1080 implementation, so we use the key anyway. See RFC 2631 & RFC 2785 for more details.'
        if not self.validate_public_key_strict(public_key):
            print(invalid_strict_msg)
        self.secret = pow(public_key, self.private, self.p)
        if cmd == 'DH1080_INIT':
            self.stage = 2
        elif cmd == 'DH1080_FINISH':
            self.stage = 3

    def show_secret(self):
        if self.secret == 0:
            raise ValueError
        return self.b64encode(hashlib.sha256(int_to_bytes(self.secret)).digest())

