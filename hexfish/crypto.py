
import os

try:
    import Crypto.Cipher.Blowfish as blowfish
except ImportError:
    try:
        import pyBlowfish as blowfish

    except ImportError:
        blowfish = None
        print("\002\0034No Blowfish implementation")
        print("This module requires one of PyCrypto, pyBlowfish")
        raise ImportError

try:
    from Crypto.Util.strxor import strxor as xorbytes
except ImportError:
    # define a slower python xor
    def xorbytes(a, b):
        '''
        xor two byte strings of equivalent length
        '''
        if len(a)!=len(b):
            raise ValueError('strings not of equivalent length')
        xored = bytearray()
        for ac, bc in zip(a, b):
            xored.append(ac ^ bc)
        return bytes(xored)

def int_to_bytes(n):
    """Integer to variable length big endian."""
    if n == 0:
        return bytes(1)
    b = []
    while n:
        b.insert(0, n&0xFF)
        n >>= 8
    return bytes(b)

def bytes_to_int(b):
    """Variable length big endian to integer."""
    n = 0
    for p in b:
        n <<= 8
        n += p
    return n

def padto(msg, length):
    """Pads 'msg' with zeroes until it's length is divisible by 'length'.
    If the length of msg is already a multiple of 'length', does nothing."""
    l = len(msg)
    if l % length:
        msg += bytes(length - l % length)
    assert len(msg) % length == 0
    return msg

def cbc_encrypt(func, data, blocksize):
    """The CBC mode. The randomy generated IV is prefixed to the ciphertext.
    'func' is a function that encrypts data in ECB mode. 'data' is the
    plaintext. 'blocksize' is the block size of the cipher."""
    assert len(data) % blocksize == 0

    iv = os.urandom(blocksize)
    assert len(iv) == blocksize

    ciphertext = iv
    for block_index in range(len(data) // blocksize):
        xored = xorbytes(data[:blocksize], iv)
        enc = func(xored)

        ciphertext += enc
        iv = enc
        data = data[blocksize:]

    assert len(ciphertext) % blocksize == 0
    return ciphertext

def cbc_decrypt(func, data, blocksize):
    """See cbc_encrypt."""
    assert len(data) % blocksize == 0

    iv = data[0:blocksize]
    data = data[blocksize:]

    plaintext = b''
    for block_index in range(len(data) // blocksize):
        temp = func(data[0:blocksize])
        temp2 = xorbytes(temp, iv)
        plaintext += temp2
        iv = data[0:blocksize]
        data = data[blocksize:]

    assert len(plaintext) % blocksize == 0
    return plaintext
