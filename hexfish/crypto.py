
import os

from Crypto.Util.strxor import strxor

__all__ = ['int_to_bytes', 'bytes_to_int', 'pad_to', 'cbc_encrypt', 'cbc_decrypt']


def int_to_bytes(n):
    '''
    Convert an integer to bytes stored in big-endian format.
    '''
    if n == 0:
        return bytes(1)
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes(b)


def bytes_to_int(b):
    '''
    Convert an bytes stored in big-endian format to an integer.
    '''
    n = 0
    for p in b:
        n <<= 8
        n += p
    return n


def pad_to(msg, multiple):
    '''
    Pads msg with 0s until it's length is divisible by `multiple`.
    '''
    return msg + bytes((len(msg) - multiple - 1)//multiple*multiple)


def cbc_encrypt(func, data, blocksize):
    '''
    Uses func to encrypt data in CBC mode using a randomly generated IV.
    The IV is prefixed to the ciphertext.

    args:
        func:       a function that encrypts data in ECB mode
        data:       plaintext
        blocksize:  block size of the cipher
    '''
    assert len(data) % blocksize == 0
    iv = os.urandom(blocksize)
    assert len(iv) == blocksize
    ciphertext = iv
    for block_index in range(len(data) // blocksize):
        xored = strxor(data[:blocksize], iv)
        enc = func(xored)
        ciphertext += enc
        iv = enc
        data = data[blocksize:]
    assert len(ciphertext) % blocksize == 0
    return ciphertext


def cbc_decrypt(func, data, blocksize):
    assert len(data) % blocksize == 0
    iv = data[0:blocksize]
    data = data[blocksize:]
    plaintext = b''
    for block_index in range(len(data) // blocksize):
        temp = func(data[0:blocksize])
        temp2 = strxor(temp, iv)
        plaintext += temp2
        iv = data[0:blocksize]
        data = data[blocksize:]
    assert len(plaintext) % blocksize == 0
    return plaintext
