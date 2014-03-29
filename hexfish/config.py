
import base64
import os
import json
import uuid
from .compat import xchat
from .crypto import blowfish

class NickInfo:
    def __init__(self, nick, config):
        # with default properties
        self.cipher = config.get((nick, 'cipher'))
        self.cbc = config.get((nick, 'cbc'))
        self.cbc_force = config.get((nick, 'cbc_force'))
        self.protect_key = config.get((nick, 'protect_key'))
        self.stealth = config.get((nick, 'stealth'))
        self.active = config.get((nick, 'active'))
        self.key = config.get((nick, 'key'))

        # internal properties
        self.nick = nick
        self._id = self.config['nick_id'].get(nick, None)
        if self._id is None:
            # randomly generate an id
            self._id = str(uuid.uuid1())
        self.dh = None
        self.config = config

    def merge_config(self):
        self.config['nick_id'][self.nick] = self._id
        self.config['id_keys'][self._id] = self.key
        json_nick_res = {}
        for key in Config.default_config['nick']['']:
            json_nick_res[key] = getattr(self, key)
        self.config['nick'][self.nick] = json_nick_res

class Config:
    default_config = {
        'max_message_length' : 300,
        # nick-specific settings (aliases don't matter)
        'nick': {
            # user-specified defaults
            '': {
                'cipher': 'blowcrypt',
                'cbc': True,
                'cbc_force': False,
                'protect_key': False,
                'active': True,
                # send request without responding
                'stealth': False,
            },
        },
        # each nick has a single alias to an id (aliases can possibly create a security problem)
        'nick_id': {},
        # each id has a single base-64 encoded key
        'id_keys': {},
    }

    def __init__(self):
        self.config = {}
        self.password = None

    def get_config_path(self):
        return os.path.join(xchat.get_info('configdir'), 'fish.json')

    def load(self, path=None, password=None):
        with open(self.get_config_path(), 'r') as fp:
            container = json.load(fp)
            if container['encrypted']:
                contents = container['contents']
                bf = blowfish.new(password.encode())
                contents = json.loads(bf.decrypt(base64.b64decode(contents.encode())).decode())
            else:
                contents = container
            return container

    def dump(self, path=None, password=None):
        contents = self.config
        encrypted = password is None
        if encrypted:
            if not 8<=len(password)<=56:
                raise ValueError('8<=len(password)<=56')
            bf = blowfish.new(password.encode())
            contents = base64.b64decode(bf.encrypt(json.dumps(contents).encode())).decode()
        container = {
            'encrypted': encrypted,
            'contents': contents
        }
        with open(self.get_config_path(), 'w') as fp:
            json.dump(container, fp)

    def get(self, keys):
        if keys[0] == 'nick' and len(keys)>=2:
            configs = []
            config = self.config
            if 'nick' in config:
                config = config['nick']
                for nick in ('', keys[0]):
                    if nick in config:
                        configs.append(config[''])
            configs.append(self.default_config['nick'])
        else:
            configs = (self.config, self.default_config)
        for config in configs:
            for key in keys:
                if key in config:
                    config = config[key]
                else:
                    break
        raise KeyError
