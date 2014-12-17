
import unittest

from hexfish.blowcrypt import *


class TestBlowCryptBase(unittest.TestCase):
    def test_b64encode(self):
        self.assertEqual(BlowCrypt.b64encode(b''), b'')
        self.assertEqual(BlowCrypt.b64encode(b'11223344'), b'OeNaN.M6haL.')
        self.assertEqual(BlowCrypt.b64encode(b'1122334455667788'), b'OeNaN.M6haL.SuNbR.QmhbP.')
        with self.assertRaises(ValueError):
            BlowCrypt.b64encode(b'1')

    def test_b64decode(self):
        self.assertEqual(BlowCrypt.b64decode(b''), b'')
        self.assertEqual(BlowCrypt.b64decode(b'OeNaN.M6haL.'), b'11223344')
        self.assertEqual(BlowCrypt.b64decode(b'OeNaN.M6haL.SuNbR.QmhbP.'), b'1122334455667788')
        with self.assertRaises(ValueError):
            BlowCrypt.b64decode(b'1')
        with self.assertRaises(ValueError):
            BlowCrypt.b64decode(b'~'*12)
        self.assertEqual(BlowCrypt.b64decode(b'OeNaN.M6haL.' + b'1', True), b'11223344')
        self.assertEqual(BlowCrypt.b64decode(b'OeNaN.M6haL.' + b'~'*12, True), b'11223344')
