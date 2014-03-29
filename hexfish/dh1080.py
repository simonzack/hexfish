
'''
irc blowfish dh-1080 encoding/decoding
'''

import os
import hashlib
from .crypto import MalformedError, int_to_bytes, bytes_to_int

g_dh1080 = 2
p_dh1080 = int('FBE1022E23D213E8ACFA9AE8B9DFAD'
               'A3EA6B7AC7A7B7E95AB5EB2DF85892'
               '1FEADE95E6AC7BE7DE6ADBAB8A783E'
               '7AF7A7FA6A2B7BEB1E72EAE2B72F9F'
               'A2BFB2A2EFBEFAC868BADB3E828FA8'
               'BADFADA3E4CC1BE7E8AFE85E9698A7'
               '83EB68FA07A77AB6AD7BEB618ACF9C'
               'A2897EB28A6189EFA07AB99A8A7FA9'
               'AE299EFA7BA66DEAFEFBEFBF0B7D8B', 16)
q_dh1080 = (p_dh1080 - 1) // 2

def dh1080_b64encode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    d = [0]*len(s)*2

    l = len(s) * 8
    m = 0x80
    i, j, k, t = 0, 0, 0, 0
    while i < l:
        if s[i >> 3] & m:
            t |= 1
        j += 1
        m >>= 1
        if not m:
            m = 0x80
        if not j % 6:
            d[k] = b64[t]
            t &= 0
            k += 1
        t <<= 1
        t %= 0x100
        #
        i += 1
    m = 5 - j % 6
    t <<= m
    t %= 0x100
    if m:
        d[k] = b64[t]
        k += 1
    d[k] = 0
    res = []
    for q in d:
        if q == 0:
            break
        res.append(q)
    return "".join(res)

def dh1080_b64decode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    buf = [0]*256
    for i in range(64):
        buf[ord(b64[i])] = i

    l = len(s)
    if l < 2:
        raise ValueError
    for i in reversed(list(range(l-1))):
        if buf[ord(s[i])] == 0:
            l -= 1
        else:
            break
    if l < 2:
        raise ValueError

    d = [0]*l
    i, k = 0, 0
    while True:
        i += 1
        if k + 1 < l:
            d[i-1] = buf[ord(s[k])] << 2
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < l:
            d[i-1] |= buf[ord(s[k])] >> 4
        else:
            break
        i += 1
        if k + 1 < l:
            d[i-1] = buf[ord(s[k])] << 4
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < l:
            d[i-1] |= buf[ord(s[k])] >> 2
        else:
            break
        i += 1
        if k + 1 < l:
            d[i-1] = buf[ord(s[k])] << 6
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < l:
            d[i-1] |= buf[ord(s[k])] % 0x100
        else:
            break
        k += 1
    return bytes(d[0:i-1])


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
