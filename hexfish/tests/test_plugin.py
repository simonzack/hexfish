
import builtins  # noinspection PyUnresolvedReferences
import io
import os
import textwrap
import unittest
import uuid
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from hexfish.plugin import *


class TestHexFishCommands(unittest.TestCase):
    def setUp(self):
        config.config = {
            'nick_id': {
                'nick1@network1': str(uuid.UUID(int=1)),
                'nick2@network2': str(uuid.UUID(int=2))
            },
            'id_key': {
                str(uuid.UUID(int=1)): '1'*8,
                str(uuid.UUID(int=2)): '2'*8,
            },
            'id_config': {
                str(uuid.UUID(int=1)): {'cbc': True}
            }
        }

    def tearDown(self):
        if os.path.exists(config.get_config_path()):
            os.remove(config.get_config_path())

    @contextmanager
    def assert_dumped(self):
        with mock.patch('hexfish.plugin.config.dump') as dump:
            yield
            dump.assert_called_with()

    @mock.patch('hexfish.plugin.xchat')
    def test_get_nick_matcher(self, xchat):
        xchat.get_info.side_effect = lambda x: {'channel': '#channel', 'network': 'network'}[x]
        self.assertEqual(hexfish_commands.get_nick_matcher(''), '#channel@network')
        self.assertEqual(hexfish_commands.get_nick_matcher('#channel'), '#channel@network')
        self.assertEqual(hexfish_commands.get_nick_matcher('#channel@network'), '#channel@network')

    def test_filter_nick(self):
        self.assertListEqual(sorted(hexfish_commands.filter_nick('**default@', True)), ['*default@'])
        self.assertListEqual(sorted(hexfish_commands.filter_nick('*@*', False)), ['nick1@network1', 'nick2@network2'])
        self.assertListEqual(sorted(hexfish_commands.filter_nick('nick*@network*', False)), [
            'nick1@network1', 'nick2@network2'
        ])

    @mock.patch('builtins.print')
    def test_show_key(self, print_):
        sr = io.StringIO()
        print_.side_effect = lambda x: sr.write(x)
        hexfish_commands.show_key(SimpleNamespace(nick='nick*@network*'))
        self.assertEqual(sr.getvalue(), textwrap.dedent('''
            nick            cipher      cbc    cbc force    active    protect    stealth         key
            --------------  ----------  -----  -----------  --------  ---------  ---------  --------
            nick1@network1  blowcrypt*  True   False*       True*     False*     False*     11111111
            nick2@network2  blowcrypt*  True*  False*       True*     False*     False*     22222222
        ''').strip())

    @mock.patch('builtins.print')
    def test_set_key(self, print_):
        with mock.patch('hexfish.plugin.config.create_id', return_value=str(uuid.UUID(int=3))), self.assert_dumped():
            hexfish_commands.set_key(SimpleNamespace(
                nick='nick3@network3', key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
            ))
            self.assertEqual(config['nick_id', 'nick3@network3'], str(uuid.UUID(int=3)))
            self.assertEqual(config['id_key', str(uuid.UUID(int=3))], 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')

    @mock.patch('builtins.print')
    def test_del_key(self, print_):
        with mock.patch('hexfish.plugin.config.create_id', return_value=str(uuid.UUID(int=3))), self.assert_dumped():
            prev_nick_id = config[('nick_id',)].copy()
            prev_id_config = config[('id_config',)].copy()
            hexfish_commands.del_key(SimpleNamespace(nick='nick*@network*'))
            self.assertEqual(config[('nick_id',)], prev_nick_id)
            self.assertEqual(config[('id_config',)], prev_id_config)
            self.assertEqual(config.has('id_key'), 1)

    @mock.patch('builtins.print')
    def test_config_key_str(self, print_):
        with self.assert_dumped():
            hexfish_commands.config_key(SimpleNamespace(nick='nick*@network*', key='cipher', value='some_cipher'))
            self.assertEqual(config[('id_config',)], {
                str(uuid.UUID(int=1)): {'cipher': 'some_cipher', 'cbc': True},
                str(uuid.UUID(int=2)): {'cipher': 'some_cipher'}
            })

    @mock.patch('builtins.print')
    def test_config_key_bool(self, print_):
        with self.assert_dumped():
            hexfish_commands.config_key(SimpleNamespace(nick='nick*@network*', key='cbc', value='1'))
            self.assertEqual(config[('id_config',)], {
                str(uuid.UUID(int=1)): {'cbc': True},
                str(uuid.UUID(int=2)): {'cbc': True}
            })

    @mock.patch('builtins.print')
    def test_encrypt(self, print_):
        with mock.patch('hexfish.plugin.add_color', side_effect=lambda color, text: text):
            sr = io.StringIO()
            print_.side_effect = lambda x: sr.write(x)
            config['id_config', config['nick_id', 'nick1@network1'], 'cbc'] = False
            hexfish_commands.encrypt(SimpleNamespace(nick='nick1@network1', unparsed='some text'))
            self.assertEqual(sr.getvalue(), '+OK 7M7bZ.8IFOz/mzvAm/ZvN7X0')

    @mock.patch('builtins.print')
    def test_encrypt_cbc(self, print_):
        with mock.patch('hexfish.plugin.add_color', side_effect=lambda color, text: text),\
                mock.patch('os.urandom', return_value=b'0'*8):
            sr = io.StringIO()
            print_.side_effect = lambda x: sr.write(x)
            config['id_config', config['nick_id', 'nick1@network1'], 'cbc'] = True
            hexfish_commands.encrypt(SimpleNamespace(nick='nick1@network1', unparsed='some text'))
            self.assertEqual(sr.getvalue(), '+OK *MDAwMDAwMDDN/2S09F4Jq10qXkgYPpJ8')

    @mock.patch('builtins.print')
    def test_decrypt(self, print_):
        with mock.patch('hexfish.plugin.add_color', side_effect=lambda color, text: text):
            sr = io.StringIO()
            print_.side_effect = lambda x: sr.write(x)
            hexfish_commands.decrypt(SimpleNamespace(nick='nick1@network1', unparsed='+OK 7M7bZ.8IFOz/mzvAm/ZvN7X0'))
            self.assertEqual(sr.getvalue(), 'some text')

    @mock.patch('builtins.print')
    def test_decrypt_cbc(self, print_):
        with mock.patch('hexfish.plugin.add_color', side_effect=lambda color, text: text):
            sr = io.StringIO()
            print_.side_effect = lambda x: sr.write(x)
            hexfish_commands.decrypt(SimpleNamespace(
                nick='nick1@network1', unparsed='+OK *MDAwMDAwMDDN/2S09F4Jq10qXkgYPpJ8'
            ))
            self.assertEqual(sr.getvalue(), 'some text')
