
'''
irc mircrypt encoding/decoding
'''

import base64
from .crypto import padto, MalformedError

def mircryption_cbc_pack(msg, cipher):
    """
    Uses strings instead of bytes as these are intended to be human-readable in irc clients.
    """
    padded = padto(msg.encode(), 8)
    return '+OK *%s' % (base64.b64encode(cipher.encrypt(padded)).decode())


def mircryption_cbc_unpack(msg, cipher):
    """
    See mircryption_cbc_pack.
    """
    if not (msg.startswith('+OK *') or msg.startswith('mcps *')):
        raise ValueError

    try:
        _, coded = msg.split('*', 1)
        raw = base64.b64decode(coded.encode())
    except TypeError:
        raise MalformedError
    if not raw:
        raise MalformedError

    try:
        padded = cipher.decrypt(raw)
    except ValueError:
        raise MalformedError
    if not padded:
        raise MalformedError

    return padded.strip(b'\x00').decode('utf-8', 'ignore')
