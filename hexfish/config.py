
import base64
import itertools
import json
import os
import uuid
from collections import OrderedDict

import xchat
from Crypto.Cipher import Blowfish

__all__ = ['Config']


class Config:
    default_config = {
        'max_message_length': 300,
        # nick-specific settings (aliases don't matter)
        'nick': {
            # user-specified defaults
            # ordered dict to pretty-print
            str(uuid.UUID(int=0)): OrderedDict([
                ('cipher', 'blowcrypt'),
                ('cbc', True),
                ('cbc_force', False),
                ('active', True),
                # protect against exchanging new keys
                ('protect_key', False),
                # do not respond to key exchanges
                ('stealth', False),
            ]),
        },
        # each nick has a single alias to an id (aliases can possibly create a security problem)
        # nick is encoded using it's host mask
        'nick_id': {'*default': str(uuid.UUID(int=0))},
        # each id has a single base-64 encoded key
        'id_keys': {},
    }

    def __init__(self, config=None, password=None):
        self.config = config or {}
        self.password = password

    @staticmethod
    def get_config_path():
        return os.path.join(xchat.get_info('configdir'), 'fish.json')

    @classmethod
    def load(cls, password=None, new=True):
        path = cls.get_config_path()
        if new and not os.path.exists(path):
            res = cls()
            res.dump(password)
            return res
        with open(cls.get_config_path(), 'r') as fp:
            container = json.load(fp)
            if container['encrypted']:
                contents = container['contents']
                bf = Blowfish.new(password.encode())
                contents = json.loads(bf.decrypt(base64.b64decode(contents.encode())).decode())
            else:
                contents = container
            return cls(container, password)

    def dump(self, password=None):
        path = self.get_config_path()
        contents = self.config
        if password:
            if not 8 <= len(password) <= 56:
                raise ValueError('8 <= len(password) <= 56')
            bf = Blowfish.new(password.encode())
            contents = base64.b64decode(bf.encrypt(json.dumps(contents).encode())).decode()
        container = {
            'encrypted': bool(password),
            'contents': contents
        }
        with open(path, 'w') as fp:
            json.dump(container, fp, indent=4)

    def find_deepest(self, keys, allow_default=True):
        keys_search = [keys]
        if allow_default and len(keys) >= 2 and keys[0] == 'nick':
            keys_search.append(('nick', str(uuid.UUID(int=0))) + keys[2:])
        config_search = [self.config]
        if allow_default:
            config_search.append(self.default_config)
        res = []
        for keys, config in itertools.product(keys_search, config_search):
            res = [(None, config)]
            for key in keys:
                if key not in config:
                    break
                config = config[key]
                res.append((key, config))
            else:
                return list(zip(*res))
        return list(zip(*res))

    def has(self, *keys):
        '''
        Returns 2 if item exists, 1 if a default exists, 0 if it doesn't exist.
        '''
        find_keys, find_configs = self.find_deepest(keys)
        if len(find_keys) < len(keys) + 1:
            return 0
        elif tuple(find_keys[1:]) != tuple(keys) or find_configs[0] == self.default_config:
            return 1
        else:
            return 2

    def __getitem__(self, keys):
        find_keys, find_configs = self.find_deepest(keys)
        if len(find_keys) < len(keys) + 1:
            raise KeyError
        return find_configs[-1]

    def __setitem__(self, keys, value):
        # always set even if values are the same, so changes in default won't break the config
        self.__getitem__(keys)
        config = self.config
        for key in keys[:-1]:
            config = config.setdefault(key, {})
        config[keys[-1]] = value

    def __delitem__(self, keys):
        find_keys, find_configs = self.find_deepest(keys)
        if len(find_keys) < len(keys) + 1:
            raise KeyError
        find_configs[-2].pop(find_keys[-1])
        prev_config = find_configs[-2]
        for key, config in zip(find_keys[-2::-1], find_configs[-3::-1]):
            if not prev_config:
                config.pop(key)
            config = prev_config

    def create_id(self):
        return str(uuid.uuid4())
