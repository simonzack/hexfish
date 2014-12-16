
import unittest
import uuid

from hexfish.config import Config


# noinspection PyStatementEffect
class TestConfig(unittest.TestCase):
    def test_has(self):
        config = Config()
        id_ = config.create_id()
        config['nick', id_, 'cipher'] = 'blowcrypt'
        self.assertEqual(config.has('nick', config.create_id(), 'does_not_exist'), 0)
        self.assertEqual(config.has('nick', config.create_id(), 'cipher'), 1)
        self.assertEqual(config.has('nick', id_, 'cipher'), 2)

    def test_get(self):
        config = Config()
        self.assertEqual(config['nick', config.create_id(), 'cipher'], 'blowcrypt')
        self.assertEqual(config['nick_id', '*default@'], str(uuid.UUID(int=0)))
        with self.assertRaises(KeyError):
            config['nick', config.create_id(), 'does_not_exist']
        with self.assertRaises(KeyError):
            config['nick_id', 'does_not_exist']

    def test_set(self):
        config = Config()
        id_ = config.create_id()
        config['nick', id_, 'cipher'] = 'blowcrypt'
        self.assertEqual(config.config, {'nick': {id_: {'cipher': 'blowcrypt'}}})

    def test_del(self):
        config = Config()
        id_ = config.create_id()
        config['nick', id_, 'cipher'] = 'blowcrypt'
        del config['nick', id_, 'cipher']
        self.assertEqual(config.config, {})
        config = Config()
        with self.assertRaises(KeyError):
            del config['nick_id', 'does_not_exist']
