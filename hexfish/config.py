
import base64
import json
import os
import uuid

import xchat
from Crypto.Cipher import Blowfish


class Config:
    default_config = {
        'max_message_length': 300,
        # nick-specific settings (aliases don't matter)
        'nick': {
            # user-specified defaults
            str(uuid.UUID(int=0)): {
                'cipher': 'blowcrypt',
                'cbc': True,
                'cbc_force': False,
                'active': True,
                # protect against exchanging new keys
                'protect_key': False,
                # do not respond to key exchanges
                'stealth': False,
            },
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

    def get(self, keys):
        if keys[0] == 'nick' and len(keys) >= 2:
            if keys[1] not in self.config.get('nick', {}):
                keys = ('nick', str(uuid.UUID(int=0))) + keys[2:]
        for config in (self.config, self.default_config):
            for key in keys:
                if key in config:
                    config = config[key]
                else:
                    break
            else:
                return config
        raise KeyError

    def set(self, keys, value):
        # always set even if values are the same, so changes in default won't break the config
        type_keys = keys
        if keys[0] == 'nick' and len(keys) >= 2:
            type_keys = ('nick', str(uuid.UUID(int=0))) + keys[2:]
        default_config = self.default_config
        config = self.config
        for key, type_key in zip(keys[:-1], type_keys):
            default_config = default_config[type_key]
            config = config.setdefault(key, type(default_config)())
        config[keys[-1]] = value

    def create_id(self):
        return str(uuid.uuid4())
