import argparse
import re
from contextlib import contextmanager, suppress

import xchat
from hexfish.blowcrypt import BlowCrypt, BlowCryptCBC, find_msg_cls
from hexfish.config import Config
from hexfish.dh1080 import DH1080
from hexfish.text import add_color, add_style
from tabulate import tabulate

__all__ = ['__module_name__', '__module_version__', '__module_description__', 'config', 'hexfish_commands', 'hexfish']

__module_name__ = 'hexfish'
__module_version__ = '1.00'
__module_description__ = 'Fish encryption in pure python.'

config = Config.load()


def format_nick(*nicks):
    return ', '.join(map(repr, sorted(nicks)))


class NoExitArgumentParser(argparse.ArgumentParser):
    def exit(self, status=0, message=None):
        if message:
            print(message.rstrip())
        raise ValueError(status)


class HexFishArgumentParser(NoExitArgumentParser):
    def __init__(self):
        # all commands are subcommands of /fish, so that namespaces have a cleaner separation
        super().__init__(prog='/fish', description=add_color('blue', self.get_version_str()))
        self.sub_parsers = self.add_subparsers(dest='mode', parser_class=NoExitArgumentParser)
        self.sub_parsers.required = True
        self.commands = {}

    @staticmethod
    def get_version_str():
        return '{} version {}: {}'.format(__module_name__, __module_version__, __module_description__)

    def register_command(self, sub_desc, arg_descs):
        def decorator(func):
            self.commands[sub_desc[0]] = func
            return func

        sub_parser = self.sub_parsers.add_parser(*sub_desc[:-1], **sub_desc[-1])
        for arg_desc in arg_descs:
            sub_parser.add_argument(*arg_desc[:-1], **arg_desc[-1])
        return decorator


class HexFishCommands:
    arg_parser = HexFishArgumentParser()

    def __init__(self):
        self.hooks = [xchat.hook_command('fish', self.main, help=self.arg_parser.format_help())]

    def __del__(self):
        for hook in self.hooks:
            xchat.unhook(hook)

    def main(self, word, word_eol, userdata):
        args = None
        print('/{}'.format(word_eol[0]))
        with suppress(ValueError):
            args = self.arg_parser.parse_args(word[1:])
        if args is not None:
            try:
                if hasattr(args, 'unparsed'):
                    args.unparsed = word_eol[-len(args.unparsed)]
                self.arg_parser.commands[args.mode](self, args)
            except ValueError as e:
                print(add_color('red', str(e)))
        return xchat.EAT_ALL

    @staticmethod
    def parse_bool(value):
        if value.lower() in ('1', 'y', 'on', 'true'):
            return True
        elif value.lower() in ('0', 'f', 'off', 'false'):
            return False
        ValueError('could not parse {!r} as a boolean'.format(value))

    @staticmethod
    def get_nick_matcher(s):
        if '@' not in s:
            s += '@{}'.format(xchat.get_info('network'))
        if s.startswith('@'):
            s = xchat.get_info('channel') + s
        return s

    @staticmethod
    def filter_nick(s, default):
        '''
        Wildcards can be escaped with '**'.
        '''
        matcher = re.escape(s).replace('\\*\\*', '**').replace('\\*', '.*').replace('**', '\\*') + '$'
        nicks = sorted(config[('nick_id',)])
        with suppress(ValueError):
            nicks.remove('*default@')
        if default:
            nicks.insert(0, '*default@')
        yield from (nick for nick in nicks if re.match(matcher, nick))

    @arg_parser.register_command(('showkey', {'help': 'Show nick key & config, wildcards allowed.'}), [
        ('nick', {'nargs': '?', 'default': ''})
    ])
    def show_key(self, args):
        nick = self.get_nick_matcher(args.nick)
        table = []
        headers = list(config['id_config', config['nick_id', '*default@']])
        table.append(['nick'] + list(' '.join(header.split('_')) for header in headers) + ['key'])
        for nick in self.filter_nick(nick, True):
            row = [nick]
            for header in headers:
                key = ('id_config', config['nick_id', nick], header)
                row.append(str(config[key]) + ('*' if config.has(*key) == 1 else ''))
            try:
                row.append(config['id_key', config['nick_id', nick]])
            except KeyError:
                row.append('')
            table.append(row)
        print(tabulate(table, headers='firstrow'))

    @arg_parser.register_command(('setkey', {'help': 'Sets a key, wildcards not allowed.'}), [
        ('nick', {'nargs': '?', 'default': ''}), ('key', {}),
    ])
    def set_key(self, args):
        nick = self.get_nick_matcher(args.nick)
        key = args.key
        try:
            BlowCrypt(key)
        except ValueError as e:
            print(e)
            return
        if not config.has('nick_id', nick):
            config['nick_id', nick] = config.create_id()
        config['id_key', config['nick_id', nick]] = key
        config.dump()
        print('key for {} set to {}'.format(format_nick(nick), key))

    @arg_parser.register_command(('delkey', {'help': 'Delete nick key, wildcards allowed.'}), [
        ('nick', {'nargs': '?', 'default': ''})
    ])
    def del_key(self, args):
        nick = self.get_nick_matcher(args.nick)
        nicks = list(self.filter_nick(nick, False))
        for nick in nicks:
            with suppress(KeyError):
                del config['id_key', config['nick_id', nick]]
        config.dump()
        print('key for {} deleted'.format(format_nick(*nicks)))

    @arg_parser.register_command(('setconfig', {'help': 'Configures a key, wildcards allowed.'}), [
        ('nick', {'nargs': '?', 'default': ''}), ('key', {}), ('value', {})
    ])
    def config_key(self, args):
        nick = self.get_nick_matcher(args.nick)
        if not config.has('id_config', config['nick_id', '*default@'], args.key):
            raise ValueError('key {} does not exist'.format(args.key))
        value = args.value
        if isinstance(config['id_config', config['nick_id', '*default@'], args.key], bool):
            value = self.parse_bool(value)
        nicks = list(self.filter_nick(nick, True))
        for nick in nicks:
            config['id_config', config['nick_id', nick], args.key] = value
        config.dump()
        print('{} for {} set to {}'.format(args.key, format_nick(*nicks), value))

    @arg_parser.register_command(('encrypt', {'help': 'Prints encrypted text.'}), [
        ('nick', {}), ('unparsed', {'nargs': '*'})
    ])
    def encrypt(self, args):
        nick = self.get_nick_matcher(args.nick)
        try:
            key = config['id_key', config['nick_id', nick]]
        except KeyError:
            raise ValueError('key for {} does not exist'.format(format_nick(nick)))
        cls = BlowCryptCBC if (
            config['id_config', config['nick_id', nick], 'cbc'] or
            config['id_config', config['nick_id', nick], 'cbc_force']
        ) else BlowCrypt
        print(add_color('blue', cls(key).pack(args.unparsed)))

    @arg_parser.register_command(('decrypt', {'help': 'Prints encrypted text.'}), [
        ('nick', {}), ('unparsed', {'nargs': '*'})
    ])
    def decrypt(self, args):
        nick = self.get_nick_matcher(args.nick)
        try:
            key = config['id_key', config['nick_id', nick]]
        except KeyError:
            raise ValueError('key for {} does not exist'.format(format_nick(nick)))
        print(add_color('blue', find_msg_cls(args.unparsed)(key).unpack(args.unparsed)))

    @arg_parser.register_command(('exchange', {'help': 'Initiates a key exchange.'}), [
        ('nick', {'nargs': '?', 'default': ''})
    ])
    def exchange(self, args):
        nick = self.get_nick_matcher(args.nick)
        hexfish.dh1080_exchange(nick)

hexfish_commands = HexFishCommands()


class HexFishHook:
    def __init__(self):
        self.in_raw_context = False
        self.context_return_value = None

    @staticmethod
    def delay(timeout, func, *args, **kwargs):
        def hook_func(userdata_):
            func(*args, **kwargs)
            xchat.unhook(hook)

        hook = xchat.hook_timer(timeout, hook_func)

    @contextmanager
    def skip_print(self, name):
        def hook_func(word, word_eol, userdata):
            return xchat.EAT_XCHAT

        hook = xchat.hook_print(name, hook_func, priority=xchat.PRI_HIGHEST)
        yield
        xchat.unhook(hook)

    def skippable(self, func):
        def decorated(*args, **kwargs):
            if self.in_raw_context:
                return self.context_return_value
            return func(*args, **kwargs)

        return decorated

    @contextmanager
    def raw_command(self, return_value):
        self.in_raw_context = True
        self.context_return_value = return_value
        yield
        self.in_raw_context = False

hexfish_hook = HexFishHook()


class HexFish:
    plain_prefix = '+p '
    decrypted_suffix = add_style('bold', add_color('blue', '\xb7'))

    def __init__(self):
        self.id_dh = {}
        self.hooks = [
            xchat.hook_command('', self.on_send_message),
            xchat.hook_command('ME', self.on_send_me),
            xchat.hook_command('MSG', self.on_send_msg),
            xchat.hook_command('NOTICE', self.on_send_notice),
            xchat.hook_server('notice', self.on_recv_notice, priority=xchat.PRI_HIGHEST),
            xchat.hook_print('Change Nick', self.on_change_nick),
            xchat.hook_unload(self.unload),
        ]
        for name in (
            'Channel Action', 'Private Action to Dialog', 'Private Action', 'Channel Message',
            'Private Message to Dialog', 'Private Message'
        ):
            xchat.hook_print(name, self.on_recv_message, name, priority=xchat.PRI_HIGHEST),

    def unload(self, userdata):
        del self

    def __del__(self):
        for hook in self.hooks:
            xchat.unhook(hook)

    @staticmethod
    def get_nick(first_word=None, network=None):
        '''
        Get the key id of a nick (if specified) or channel.
        '''
        if first_word:
            nick = first_word.split('!')[0] if '!' in first_word else first_word
        else:
            nick = xchat.get_info('channel')
        return '{}@{}'.format(nick, network or xchat.get_info('network'))

    @staticmethod
    def emit_print(event_name, nick, msg, *args, context=None):
        if not context:
            context = xchat.get_context()
        color = '2'
        for highlight in [xchat.get_info('nick')] + xchat.get_prefs('irc_extra_hilight').split(','):
            if highlight and highlight in msg:
                if event_name == 'Channel Message':
                    event_name = 'Channel Msg Hilight'
                elif event_name == 'Channel Action':
                    event_name = 'Channel Action Hilight'
                color = '3'
        context.emit_print(event_name, nick, msg, *args)
        xchat.command('GUI COLOR {}'.format(color))

    def dh1080_exchange(self, nick):
        '''
        Initiate a key exchange.
        '''
        if nick.startswith('#'):
            print('can\'t exchange keys with a channel')
            return
        if not config.has('nick_id', nick):
            config['nick_id', nick] = config.create_id()
        if config['id_config', config['nick_id', nick], 'protect']:
            print(add_color('red', 'key protection is on for {}, exchange denied'.format(format_nick(nick))))
            return
        self.id_dh[config['nick_id', nick]] = DH1080()
        dh = self.id_dh[config['nick_id', nick]]
        with hexfish_hook.raw_command(xchat.EAT_NONE):
            xchat.command('NOTICE {} {}'.format(
                nick.split('@')[0], dh.send_request(config['id_config', config['nick_id', nick], 'cbc']))
            )
        config.dump()

    def on_dh1080_init(self, nick, msg):
        '''
        Reply to key exchange initiated by somebody else. Key exchanges already in progress are assumed to have failed
        (e.g. network problems) and discarded.
        '''
        if not config.has('nick_id', nick):
            config['nick_id', nick] = config.create_id()
        if config['id_config', config['nick_id', nick], 'protect']:
            xchat.command('NOTICE {} {}'.format(
                nick.split('@')[0], add_color('red', 'key protection is on, exchange denied'))
            )
            print(add_color('red', 'key protection is on for {}, exchange denied'.format(format_nick(nick))))
            return
        if config['id_config', config['nick_id', nick], 'stealth']:
            print('stealth is on for {}, exchange denied'.format(format_nick(nick)))
            return
        # discard existing key exchanges
        self.id_dh[config['nick_id', nick]] = DH1080()
        dh = self.id_dh[config['nick_id', nick]]
        try:
            dh.receive_any(msg)
        except ValueError as e:
            print(e)
            return
        with hexfish_hook.raw_command(xchat.EAT_NONE):
            xchat.command('NOTICE {} {}'.format(nick.split('@')[0], dh.send_response()))
        # check if dh was discarded
        if self.id_dh[config['nick_id', nick]] != dh:
            return
        dh = self.id_dh.pop(config['nick_id', nick])
        config['id_key', config['nick_id', nick]] = dh.get_secret().decode()
        config['id_config', config['nick_id', nick], 'cbc'] = dh.cbc
        config['id_config', config['nick_id', nick], 'active'] = True
        config.dump()
        print('{} init from {} succeeded'.format('DH1080 (CBC)' if dh.cbc else 'DH1080', format_nick(nick)))
        print('Key set to {}'.format(config['id_key', config['nick_id', nick]]))

    def on_dh1080_finish(self, nick, msg):
        '''
        Finish the key exchange upon receiving the target's response.
        '''
        # check if dh exists
        if not config.has('nick_id', nick) or config['nick_id', nick] not in self.id_dh:
            print('DH1080 finish received from {} but no request was sent'.format(format_nick(nick)))
            return
        dh = self.id_dh.pop(config['nick_id', nick])
        try:
            dh.receive_any(msg)
        except ValueError as e:
            print(e)
            return
        config['id_key', config['nick_id', nick]] = dh.get_secret().decode()
        config['id_config', config['nick_id', nick], 'cbc'] = dh.cbc
        config['id_config', config['nick_id', nick], 'active'] = True
        config.dump()
        print('{} finish from {} succeeded'.format('DH1080 (CBC)' if dh.cbc else 'DH1080', format_nick(nick)))
        print('Key set to {}'.format(config['id_key', config['nick_id', nick]]))

    def on_dh1080(self, nick, msg):
        # delay to display exchange status after the key exchange notice is printed
        if msg.startswith('DH1080_INIT'):
            hexfish_hook.delay(0, self.on_dh1080_init, nick, msg)
            return xchat.EAT_PLUGIN
        elif msg.startswith('DH1080_FINISH'):
            hexfish_hook.delay(0, self.on_dh1080_finish, nick, msg)
            return xchat.EAT_PLUGIN
        else:
            raise ValueError

    def encrypt(self, nick, msg):
        if msg.startswith(self.plain_prefix):
            return msg[len(self.plain_prefix):]
        if not config['id_config', config['nick_id', nick], 'active']:
            raise ValueError
        key = config['id_key', config['nick_id', nick]]
        cls = BlowCryptCBC if (
            config['id_config', config['nick_id', nick], 'cbc'] or
            config['id_config', config['nick_id', nick], 'cbc_force']
        ) else BlowCrypt
        return cls(key).pack(msg)

    # noinspection PyUnreachableCode
    def decrypt(self, nick, msg):
        if msg.startswith(self.plain_prefix):
            return msg
        key = config['id_key', config['nick_id', nick]]
        cls = find_msg_cls(msg)
        with suppress(ValueError):
            return '{}{}'.format(cls(key).unpack(msg), self.decrypted_suffix)
        with suppress(ValueError):
            res = cls(key).unpack(msg, True)
            print('partially decrypted {!r}'.format(msg))
            return '{}{}'.format(res, add_color('yellow', '<incomplete>'))
        print('could not decrypt {!r}'.format(msg))
        return msg

    # noinspection PyUnreachableCode
    def on_recv_message(self, word, word_eol, userdata):
        nick = self.get_nick(word[0][1:])
        key_nick = self.get_nick() if self.get_nick().startswith('#') else self.get_nick(word[0])
        msg = word_eol[1]
        # remove mode chars
        if len(word_eol) >= 3:
            msg = msg[:-2]
        with suppress(ValueError, KeyError):
            msg = self.decrypt(key_nick, msg)
            self.emit_print(userdata, nick.split('@')[0], msg)
            return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    # noinspection PyUnreachableCode
    def on_recv_notice(self, word, word_eol, userdata):
        nick = self.get_nick(word[0][1:])
        msg = word_eol[3]
        for prefix in (':-', ':'):
            if msg.startswith(prefix):
                msg = msg[len(prefix):]
                break
        with suppress(ValueError, KeyError):
            return self.on_dh1080(nick, msg)
        with suppress(ValueError, KeyError):
            msg = self.decrypt(nick, msg)
            self.emit_print('Notice', nick.split('@')[0], msg)
            return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    # noinspection PyUnreachableCode
    def on_send_message(self, word, word_eol, userdata):
        nick = self.get_nick()
        msg = word_eol[0]
        with suppress(ValueError, KeyError):
            msg_ = self.encrypt(nick, msg)
            self.emit_print('Your Message', xchat.get_info('nick'), msg)
            xchat.command('PRIVMSG {} :{}'.format(nick.split('@')[0], msg_))
            return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    # noinspection PyUnreachableCode
    @hexfish_hook.skippable
    def on_send_me(self, word, word_eol, userdata):
        if len(word) == 1:
            return xchat.EAT_NONE
        nick = self.get_nick()
        msg = word_eol[1]
        with suppress(ValueError, KeyError):
            msg_ = self.encrypt(nick, msg)
            self.emit_print('Your Action', xchat.get_info('nick'), msg)
            with hexfish_hook.raw_command(xchat.EAT_NONE), hexfish_hook.skip_print('Your Action'):
                xchat.command('ME {}'.format(msg_))
            return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    @hexfish_hook.skippable
    def on_send_msg(self, word, word_eol, userdata):
        context = xchat.find_context(channel=word[1])
        if context:
            nick = self.get_nick(word[1])
            msg = word_eol[2]
            with suppress(ValueError, KeyError):
                msg_ = self.encrypt(nick, msg)
                self.emit_print('Your Message', xchat.get_info('nick'), msg, context=context)
                with hexfish_hook.raw_command(xchat.EAT_NONE), hexfish_hook.skip_print('Your Message'):
                    xchat.command('MSG {} {}'.format(nick.split('@')[0], msg_))
                return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    @hexfish_hook.skippable
    def on_send_notice(self, word, word_eol, userdata):
        context = xchat.find_context(channel=word[1])
        if context:
            nick = self.get_nick(word[1])
            msg = word_eol[2]
            with suppress(ValueError, KeyError):
                msg_ = self.encrypt(nick, msg)
                self.emit_print('Notice Send', nick.split('@')[0], msg)
                with hexfish_hook.raw_command(xchat.EAT_NONE), hexfish_hook.skip_print('Notice Send'):
                    xchat.command('NOTICE {} {}'.format(nick.split('@')[0], msg_))
                return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    def on_change_nick(self, word, word_eol, userdata):
        prev_nick = self.get_nick(word[0])
        nick = self.get_nick(word[1])
        if not config.has('nick_id', prev_nick):
            return xchat.EAT_NONE
        config['nick_id', nick] = config['nick_id', prev_nick]
        config.dump()
        return xchat.EAT_NONE

hexfish = HexFish()
