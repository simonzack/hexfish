
'''
irc blowfish dh-1080 encoding/decoding
'''

import base64
import os
import hashlib
from .crypto import MalformedError, int_to_bytes, bytes_to_int

g_dh1080 = 2
p_dh1080 = int(
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
q_dh1080 = (p_dh1080 - 1) // 2

def dh1080_b64encode(s):
    '''
    utf-7 base64 encode without padding characters, padding instead with 0 bits
    '''
    res = base64.b64encode(s)
    if b'=' in res:
        return res.rstrip(b'=')
    else:
        return res + b'='

def dh1080_b64decode(s):
    '''
    utf-7 base64 encode without padding characters, padding instead with 0 bits
    '''
    # remove trailing 'A' if it's just for padding
    if len(s)%4==1:
        s = s[:-1]
    # add padding characters
    s += b'='*((-len(s))%4)
    return base64.b64decode(s)

def dh_validate_public(public, q, p):
    """See RFC 2631 section 2.1.5."""
    return 1 == pow(public, q, p)


class DH1080Ctx:
    """DH1080 context."""
    def __init__(self):
        self.public = 0
        self.private = 0
        self.secret = 0
        self.state = 0

        bits = 1080
        while True:
            self.private = bytes_to_int(os.urandom(bits//8))
            self.public = pow(g_dh1080, self.private, p_dh1080)
            if 2 <= self.public <= p_dh1080 - 1 and \
               dh_validate_public(self.public, q_dh1080, p_dh1080) == 1:
                break

def dh1080_pack(ctx):
    """
    Uses strings as designed to be human readable in irc.
    """
    if ctx.state == 0:
        ctx.state = 1
        cmd = "DH1080_INIT"
    else:
        cmd = "DH1080_FINISH"
    return "%s %s" % (cmd,dh1080_b64encode(int_to_bytes(ctx.public)))

def dh1080_unpack(msg, ctx):
    if not msg.startswith("DH1080_"):
        raise ValueError

    invalidmsg = "Key does not conform to RFC 2631. This check is not performed by any DH1080 implementation, so we use the key anyway. See RFC 2631 & RFC 2785 for more details."

    if ctx.state == 0:
        if not msg.startswith("DH1080_INIT "):
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(' ', 1)
            public = bytes_to_int(dh1080_b64decode(public_raw))

            if not 1 < public < p_dh1080:
                raise MalformedError

            if not dh_validate_public(public, q_dh1080, p_dh1080):
                print(invalidmsg)
                pass

            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError

    elif ctx.state == 1:
        if not msg.startswith("DH1080_FINISH "):
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(' ', 1)
            public = bytes_to_int(dh1080_b64decode(public_raw))

            if not 1 < public < p_dh1080:
                raise MalformedError

            if not dh_validate_public(public, q_dh1080, p_dh1080):
                print(invalidmsg)
                pass

            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError

    return True


def dh1080_secret(ctx):
    if ctx.secret == 0:
        raise ValueError
    return dh1080_b64encode(hashlib.sha256(int_to_bytes(ctx.secret)).digest())
