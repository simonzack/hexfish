
import argparse
import base64
import binascii
import re
import time
from contextlib import suppress

import xchat
from tabulate import tabulate

from hexfish.blowcrypt import BlowCrypt, BlowCryptCBC, is_cbc
from hexfish.config import Config
from hexfish.dh1080 import DH1080
from hexfish.text import add_color

__all__ = ['__module_name__', '__module_version__', '__module_description__', 'config', 'hexfish_commands', 'hexfish']

__module_name__ = 'hexfish'
__module_version__ = '5.00b'
__module_description__ = 'Fish encryption in pure python.'


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
    def format_nick(*nicks):
        return ', '.join(map(repr, sorted(nicks)))

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

    @arg_parser.register_command(('show_key', {'help': 'Show nick key & config, wildcards allowed.'}), [
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
            row.append(config['id_key', config['nick_id', nick]] if nick != '*default@' else '')
            table.append(row)
        print(tabulate(table, headers='firstrow'))

    @arg_parser.register_command(('set_key', {'help': 'Sets a key, wildcards not allowed.'}), [
        ('nick', {'nargs': '?', 'default': ''}), ('key', {}),
    ])
    def set_key(self, args):
        nick = self.get_nick_matcher(args.nick)
        key = args.key
        try:
            if not 8 <= len(base64.b64decode(key)) <= 56:
                raise ValueError('8 <= len(base64.b64decode(key)) <= 56')
        except binascii.Error:
            raise ValueError('key is not base64-encoded')
        if not config.has('nick_id', nick):
            config['nick_id', nick] = config.create_id()
        config['id_key', config['nick_id', nick]] = key
        config.dump()
        print('key for {} set to {}'.format(self.format_nick(nick), key))

    @arg_parser.register_command(('del_key', {'help': 'Delete nick key, wildcards allowed.'}), [
        ('nick', {'nargs': '?', 'default': ''})
    ])
    def del_key(self, args):
        nick = self.get_nick_matcher(args.nick)
        nicks = list(self.filter_nick(nick, False))
        for nick in nicks:
            with suppress(KeyError):
                del config['id_key', config['nick_id', nick]]
        config.dump()
        print('key for {} deleted'.format(self.format_nick(*nicks)))

    @arg_parser.register_command(('config', {'help': 'Configures a key, wildcards allowed.'}), [
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
        print('{} for {} set to {}'.format(args.key, self.format_nick(*nicks), value))

    @arg_parser.register_command(('encrypt', {'help': 'Prints encrypted text.'}), [
        ('nick', {}), ('unparsed', {'nargs': '*'})
    ])
    def encrypt(self, args):
        nick = self.get_nick_matcher(args.nick)
        try:
            key = config['id_key', config['nick_id', nick]]
        except KeyError:
            raise ValueError('key for {} does not exist'.format(self.format_nick(nick)))
        cls = BlowCryptCBC if config['id_config', config['nick_id', nick], 'cbc'] else BlowCrypt
        print(add_color('blue', cls(key).pack(args.unparsed)))

    @arg_parser.register_command(('decrypt', {'help': 'Prints encrypted text.'}), [
        ('nick', {}), ('unparsed', {'nargs': '*'})
    ])
    def decrypt(self, args):
        nick = self.get_nick_matcher(args.nick)
        try:
            key = config['id_key', config['nick_id', nick]]
        except KeyError:
            raise ValueError('key for {} does not exist'.format(self.format_nick(nick)))
        cls = BlowCryptCBC if is_cbc(args.unparsed) else BlowCrypt
        print(add_color('blue', cls(key).unpack(args.unparsed)))


# class HexFish:
#     def __init__(self):
#         self.active = True
#         self.__KeyMap = {}
#         self.__TargetMap = {}
#         self.__lockMAP = {}
#         self._hooks = [
#             xchat.hook_server('notice', self.on_notice, priority=xchat.PRI_HIGHEST),
#             xchat.hook_server('332', self.server_332_topic, priority=xchat.PRI_HIGHEST),
#
#             xchat.hook_command('', self.out_message),
#             xchat.hook_command('ME+', self.out_message_cmd),
#             xchat.hook_command('MSG', self.out_message_cmd),
#             xchat.hook_command('MSG+', self.out_message_force),
#             xchat.hook_command('NOTICE', self.out_message_cmd),
#             xchat.hook_command('NOTICE+', self.out_message_force),
#
#             xchat.hook_print('Notice Send', self.on_notice_send, 'Notice', priority=xchat.PRI_HIGHEST),
#             xchat.hook_print('Change Nick', self.nick_trace),
#             xchat.hook_print('Channel Action', self.in_message, 'Channel Action', priority=xchat.PRI_HIGHEST),
#             xchat.hook_print(
#                 'Private Action to Dialog', self.in_message, 'Private Action to Dialog', priority=xchat.PRI_HIGHEST
#             ),
#             xchat.hook_print('Private Action ', self.in_message, 'Private Action', priority=xchat.PRI_HIGHEST),
#             xchat.hook_print('Channel Message', self.in_message, 'Channel Message', priority=xchat.PRI_HIGHEST),
#             xchat.hook_print(
#                 'Private Message to Dialog', self.in_message, 'Private Message to Dialog', priority=xchat.PRI_HIGHEST
#             ),
#             xchat.hook_print('Private Message', self.in_message, 'Private Message', priority=xchat.PRI_HIGHEST),
#             xchat.hook_unload(self.unload),
#         ]
#
#     def unload(self, userdata):
#         del self
#
#     def __del__(self):
#         for hook in self._hooks:
#             xchat.unhook(hook)
#
#     ## incoming notice received
#     def on_notice(self, word, word_eol, userdata):
#         ## check if this is not allready processed
#         if self.__chk_proc():
#             return xchat.EAT_NONE
#
#         ## check if DH Key Exchange
#         if word_eol[3].startswith(':DH1080_FINISH'):
#             return self.dh1080_finish(word, word_eol, userdata)
#         elif word_eol[3].startswith(':DH1080_INIT'):
#             return self.dh1080_init(word, word_eol, userdata)
#
#         ## check for encrypted Notice
#         elif word_eol[3].startswith('::+OK ') or word_eol[3].startswith('::mcps '):
#
#             ## rewrite data to pass to default inMessage function
#             ## change full ident to nick only
#             nick = self.get_nick(word[0])
#             target = word[2]
#             speaker = nick
#             ## strip :: from message
#             message = word_eol[3][2:]
#             if target.startswith("#"):
#                 id_ = self.get_id()
#                 speaker = "## %s" % speaker
#             else:
#                 id_ = self.get_id(nick=nick)
#             #print "DEBUG(crypt): key: %r word: %r" % (id,word,)
#             key = self.find_key(id_)
#             ## if no key found exit
#             if not key:
#                 return xchat.EAT_NONE
#
#             ## decrypt the message
#             try:
#                 sndmessage = self.decrypt(key,message)
#             except:
#                 sndmessage = None
#             is_cbc=0
#             if message.startswith("+OK *"):
#                 is_cbc=1
#             failcol = ""
#
#             ## if decryption was possible check for invalid chars
#             if sndmessage:
#                 try:
#                     message = sndmessage
#                     ## mark nick for encrypted msgg
#                     speaker = "%s %s" % ("?????"*(1+is_cbc),speaker)
#                 except UnicodeError:
#                     try:
#                         message = str(sndmessage,encoding='iso8859-1',errors='ignore').encode('UTF8')
#                         ## mark nick for encrypted msgg
#                         speaker = "%s %s" % ("?????"*(1+is_cbc),speaker)
#                     except:
#                         raise
#                     ## send the message to local xchat
#                     #self.emit_print(userdata,speaker,message)
#                     #return xchat.EAT_XCHAT
#                 except:
#                     ## mark nick with a question mark
#                     speaker = "?%s" % speaker
#                     failcol = "\003"
#             else:
#                 failcol = "\003"
#             ## mark the message with \003, it failed to be processed and there for the \003+OK  will no longer be excepted as encrypted so it wont loop
#             self.emit_print(userdata,speaker,"%s%s" % (failcol,message))
#             return xchat.EAT_XCHAT
# #            return self.inMessage([nick,msg], ["%s %s" % (nick,msg),msg], userdata)
#
#         ## ignore everything else
#         else:
#             #print "DEBUG: %r %r %r" % (word, word_eol, userdata)
#             return xchat.EAT_NONE
#
#     ## local notice send messages
#     def on_notice_send(self, word, word_eol, userdata):
#         ## get current nick
#         target = xchat.get_context().get_info('nick')
#         #print "DEBUG_notice_send: %r - %r - %r %r" % (word,word_eol,userdata,nick)
#
#         ## check if this is not allready processed
#         if self.__chk_proc(target=target):
#             return xchat.EAT_NONE
#
#         ## get the speakers nick only from full ident
#         speaker = self.get_nick(word[0])
#
#         ## strip first : from notice
#         message = word_eol[1][1:]
#         if message.startswith('+OK ') or message.startswith('mcps '):
#             ## get the key id from the speaker
#             id_ = self.get_id(nick=speaker)
#             key = self.find_key(id_)
#
#             ## if no key available for the speaker exit
#             if not key:
#                 return xchat.EAT_NONE
#
#             ## decrypt the message
#             sndmessage = self.decrypt(key,message)
#             is_cbc = 0
#             if message.startswith("+OK *"):
#                 is_cbc = 1
#                 if not target.startswith("#"):
#                     ## if we receive a messge with CBC enabled we asume the partner can also except it so activate it
#                     key.cbc_mode = True
#
#             ## if decryption was possible check for invalid chars
#
#             if sndmessage:
#                 try:
#                     message = sndmessage
#                     ## mark nick for encrypted msgg
#                     speaker = "%s %s" % ("?????"*(1+is_cbc),speaker)
#                 except:
#                     ## mark nick with a question mark
#                     speaker = "?%s" % speaker
#                     ## send original message because invalid chars
#                     message = message
#
#             ## send the message back to incoming notice but with locked target status so it will not be processed again
#             self.emit_print("Notice Send",speaker,message,target=target)
#             return xchat.EAT_XCHAT
#         return xchat.EAT_NONE
#
#     ## incoming messages
#     def in_message(self, word, word_eol, userdata):
#         ## if message is allready processed ignore
#         if self.__chk_proc() or len(word_eol) < 2:
#             return xchat.EAT_PLUGIN
#
#         speaker = word[0]
#         message = word_eol[1]
#         #print "DEBUG(INMsg): %r - %r - %r" % (word,word_eol,userdata)
#         # if there is mode char, remove it from the message
#         if len(word_eol) >= 3:
#             #message = message[ : -(len(word_eol[2]) + 1)]
#             message = message[:-2]
#
#         ## check if message is crypted
#         if message.startswith('+OK ') or message.startswith('mcps '):
#             target = None
#             if userdata == "Private Message":
#                 target = speaker
#             id_ = self.get_id(nick=target)
#             target,network = id_
#             key = self.find_key(id_)
#
#             ## if no key found exit
#             if not key:
#                 return xchat.EAT_NONE
#
#             ## decrypt the message
#             try:
#                 sndmessage = self.decrypt(key,message)
#             except:
#                 sndmessage = None
#             is_cbc=0
#             if message.startswith("+OK *"):
#                 is_cbc=1
#                 if not target.startswith("#"):
#                     ## if we receive a messge with CBC enabled we asume the partner can also except it so activate it
#                     key.cbc_mode = True
#
#             failcol = ""
#
#             ## if decryption was possible check for invalid chars
#             if sndmessage:
#                 try:
#                     message = sndmessage
#                     ## mark nick for encrypted msgg
#                     speaker = "%s %s" % ("?????"*(1+is_cbc),speaker)
#                 except UnicodeError:
#                     try:
#                         message = str(sndmessage,encoding='iso8859-1',errors='ignore').encode('UTF8')
#                         ## mark nick for encrypted msgg
#                         speaker = "%s %s" % ("?????"*(1+is_cbc),speaker)
#                     except:
#                         raise
#                     ## send the message to local xchat
#                     #self.emit_print(userdata,speaker,message)
#                     #return xchat.EAT_XCHAT
#                 except:
#                     ## mark nick with a question mark
#                     speaker = "?%s" % speaker
#                     failcol = "\003"
#             else:
#                 failcol = "\003"
#             ## mark the message with \003, it failed to be processed and there for the \003+OK  will no longer be excepted as encrypted so it wont loop
#             self.emit_print(userdata,speaker,"%s%s" % (failcol,message))
#             return xchat.EAT_ALL
#
#         return xchat.EAT_NONE
#
#     def decrypt(self, key, msg):
#         ret = None
#
#         # check for CBC
#         if 3 <= msg.find(' *') <= 4:
#             crypt_cls = BlowCryptCBC
#         else:
#             crypt_cls = BlowCrypt
#
#         bf = crypt_cls(key.key.encode())
#         try:
#             ret = bf.decrypt(msg)
#         except ValueError:
#             # try to decrypt a part of the message
#             try:
#                 cut = (len(msg) - 4)%12
#                 if cut > 0:
#                     msg = msg[:cut *-1]
#                     ret = "%s%s" % ( crypt_cls.decrypt(msg), " \0038<<incomplete>>" * (cut>0))
#             except ValueError:
#                 pass
#         if ret is None:
#             print("Decrypt Error")
#         return ret
#
#     ## mark outgoing message being  prefixed with a command like /notice /msg ...
#     def out_message_cmd(self, word, word_eol, userdata):
#         return self.out_message(word, word_eol, userdata,command=True)
#
#     ## mark outgoing message being prefixed with a command that enforces encryption like /notice+ /msg+
#     def out_message_force(self, word, word_eol, userdata):
#         return self.out_message(word, word_eol, userdata, force=True,command=True)
#
#     ## the outgoing messages will be proccesed herre
#     def out_message(self, word, word_eol, userdata,force=False,command=False):
#
#         ## check if allready processed
#         if self.__chk_proc():
#             return xchat.EAT_NONE
#
#         ## get the id
#         id_ = self.get_id()
#         target,network = id_
#         ## check if message is prefixed wit a command like /msg /notice
#         action = False
#         if command:
#
#             if len(word) < (word[0].upper().startswith("ME") and 2 or 3):
#                 print("Usage: %s <nick/channel> <message>, sends a %s.%s are a type of message that should be auto reacted to" % (word[0],word[0],word[0]))
#                 return xchat.EAT_ALL
#             ## notice and notice+
#             if word[0].upper().startswith("NOTICE"):
#                 command = "NOTICE"
#             else:
#                 command = "PRIVMSG"
#             if word[0].upper().startswith("ME"):
#                 action = True
#                 message = word_eol[1]
#             else:
#                 ## the target is first parameter after the command, not the current channel
#                 target = word[1]
#                 ## change id
#                 id_ = (target,network)
#                 ## remove command and target from message
#                 message = word_eol[2]
#         else:
#             command = "PRIVMSG"
#             message = word_eol[0]
#
#         sendmsg = ''
#         ## try to get a key for the target id
#         key = self.find_key(id_)
#
#         ## my own nick
#         nick = xchat.get_context().get_info('nick')
#
#         #print "DEBUG(outMsg1)(%r) %r : %r %r" % (id,xchat.get_context().get_info('network'),word,nick)
#
#         ## if we don't have a key exit
#         if not key:
#             return xchat.EAT_NONE
#
#         ## if the key object is there but the key deleted or marked not active...and force is not set by command like /msg+ or /notice+
#         if key.key is None or (key.active == False and not force):
#             return xchat.EAT_NONE
#
#         ## encrypt message
#         maxlen = self.config['MAXMESSAGELENGTH']
#         cutmsg = message
#         messages = []
#         sendmessages = []
#         while len(cutmsg) >0:
#             sendmessages.append(self.encrypt(key,cutmsg[:maxlen]))
#             messages.append(cutmsg[:maxlen])
#             cutmsg = cutmsg[maxlen:]
#         ## mark the nick with ????? for encrypted messages
#         nick = "%s %s" % ("?????"*(1+key.cbc_mode),nick)
#
#         #print "DEBUG(outMsg2): %r %r %r %r" % (command,message,nick,target)
#
#         for sendmsg in sendmessages:
#             ## lock the target
#             self.__lock_proc(True)
#             ## send the command (PRIVMSG / NOTICE)
#             if action:
#                 sendmsg = "\001ACTION %s\001" % sendmsg
#             xchat.command('%s %s :%s' % (command,target, sendmsg))
#             ## release the lock
#             self.__lock_proc(False)
#
#         for message in messages:
#             ## if it is no notice it must be send plaintext to xchat for you
#             if command == "PRIVMSG":
#                 if action:
#                     self.emit_print('Channel Action',  nick, message)
#                 else:
#                     target_tab= xchat.find_context(channel=target)
#                     if not target_tab and target_tab != xchat.get_context():
#                         self.emit_print('Message Send',  "%s %s" % ("?????"*(1+key.cbc_mode),target), message)
#                     else:
#                         self.emit_print('Your Message',  nick, message, to_context=target_tab)
#         return xchat.EAT_ALL
#
#     def encrypt(self,key, msg):
#         if key.cbc_mode:
#             encrypt_cls = BlowCryptCBC
#         else:
#             encrypt_cls = BlowCrypt
#         return encrypt_cls(key.key.encode()).encrypt(msg)
#
#     ## send message to local xchat and lock it
#     def emit_print(self,userdata,speaker,message,target=None,to_context=None):
#         if not to_context:
#             to_context = xchat.get_context()
#         if userdata is None:
#             ## if userdata is none its possible Notice
#             userdata = "Notice"
#         if not target:
#             ## if no special target for the lock is set, make it the speaker
#             target = speaker
#         ## lock the processing of that message
#         self.__lock_proc(True,target=target)
#         ## check for Highlight
#         for hl in [xchat.get_info('nick')] + xchat.get_prefs("irc_extra_hilight").split(","):
#             if len(hl) >0 and message.find(hl) > -1:
#                 if userdata == "Channel Message":
#                     userdata = "Channel Msg Hilight"
#                 xchat.command("GUI COLOR 3")
#         ## send the message
#         to_context.emit_print(userdata,speaker, message.replace('\0',''))
#         ## release the lock
#         self.__lock_proc(False,target=target)
#
#     ## set or release the lock on the processing to avoid loops
#     def __lock_proc(self,state,target=None):
#         ctx = xchat.get_context()
#         if not target:
#             ## if no target set, the current channel is the target
#             target = ctx.get_info('channel')
#         ## the lock is NETWORK-TARGET
#         id_ = "%s-%s" % (ctx.get_info('network'),target)
#         self.__lockMAP[id_] = state
#
#     ## check if that message is allready processed to avoid loops
#     def __chk_proc(self,target=None):
#         ctx = xchat.get_context()
#         if not target:
#             ## if no target set, the current channel is the target
#             target = ctx.get_info('channel')
#         id_ = "%s-%s" % (ctx.get_info('network'),target)
#         return self.__lockMAP.get(id_,False)
#
#     @staticmethod
#     def get_id(nick=None, network=None):
#         '''
#         Get the key id of a nick (if specified) or channel.
#         '''
#         return '{}@{}'.format(nick or xchat.get_info('channel'), network or xchat.get_info('network'))
#
#     def find_key(self, id_, create=None):
#         key = self.__KeyMap.get(id_,None)
#         target, network = id_
#         networkmap = self.__TargetMap.get(network,None)
#         if not networkmap:
#             networkmap = {}
#             self.__TargetMap[network] = networkmap
#         if not key:
#             lastaxx,key = networkmap.get(target,(-1,None))
#         else:
#             for _target,_key in [x for x in networkmap.items() if x[1] == key]:
#                 if _target != target:
#                     del networkmap[_target]
#         if not key and create:
#             key = create
#         if key:
#             self.__TargetMap[network][target] = (int(time.time()),key)
#         return key
#
#     ## return the nick only
#     def get_nick(self,full):
#         if full[0] == ':':
#             full = full[1:]
#         try:
#             ret = full[:full.index('!')]
#         except ValueError:
#             ret  = full
#         return ret
#
#     ## start the DH1080 Key Exchange
#     def key_exchange(self, word, word_eol, userdata):
#         id_ = self.get_id()
#         target,network = id_
#         if len(word) >1:
#             target = word[1]
#             id_ = (target,network)
#
#         ## XXX chan notice - what should happen when keyx is send to channel trillian seems to accept it and send me a key --
#         if target.startswith("#"):
#             print("Channel Exchange not implemented")
#             return xchat.EAT_ALL
#
#         ## create DH
#         dh = DH1080()
#
#         self.__KeyMap[id_] = self.find_key(id_,create=SecretKey(dh,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
#         self.__KeyMap[id_].keyname = id_
#         self.__KeyMap[id_].dh = dh
#
#         ## lock the target
#         self.__lock_proc(True)
#         ## send key with notice to target
#         xchat.command('NOTICE {} {}'.format(target, dh.send_request(self.config['DEFAULTCBC'])))
#         ## release the lock
#         self.__lock_proc(False)
#
#         ## save the key storage
#         self.save_db()
#         return xchat.EAT_ALL
#
#     ## Answer to KeyExchange
#     def dh1080_init(self, word, word_eol, userdata):
#         id_ = self.get_id(nick=self.get_nick(word[0]))
#         target,network = id_
#         message = word_eol[3]
#         key = self.find_key(id_,create=SecretKey(None,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
#
#         ## Protection against a new key if "/PROTECTKEY" is on for nick
#         if key.protect_mode:
#             print("%sKEYPROTECTION: %s on %s" % (COLOR['red'],target,network))
#             xchat.command("notice %s %s KEYPROTECTION:%s %s" % (target,self.config['PLAINTEXTMARKER'],COLOR['red'],target))
#             return xchat.EAT_ALL
#
#         ## Stealth Check
#         if self.config['FISHSTEALTH']:
#             print("%sSTEALTHMODE: %s tried a keyexchange on %s" % (COLOR['green'],target,network))
#             return xchat.EAT_ALL
#
#         dh = DH1080()
#         dh.receive_any(message[1:])
#         key.key = dh.get_secret()
#         key.keyname = id_
#
#         ## lock the target
#         self.__lock_proc(True)
#         ## send key with notice to target
#         xchat.command('NOTICE {} {}'.format(target, dh.send_response()))
#
#         ## release the lock
#         self.__lock_proc(False)
#         self.__KeyMap[id_] = key
#         print("DH1080 Init: {} on {} {}".format(target, network, 'with CBC mode' if len(word)>5 and word[5]=='CBC' else ''))
#         print("Key set to %r" % (key.key,))
#         ## save key storage
#         self.save_db()
#         return xchat.EAT_ALL
#
#     ## Answer from targets init
#     def dh1080_finish(self, word, word_eol, userdata):
#         id_ = self.get_id(nick=self.get_nick(word[0]))
#         target,network = id_
#         ## XXX if not explicit send to the Target the received key is discarded - chan exchange
#         if id_ not in self.__KeyMap:
#             print("Invalid DH1080 Received from %s on %s" % (target,network))
#             return xchat.EAT_NONE
#         key = self.__KeyMap[id_]
#         try:
#             message = "%s %s" % (word[3],word[4])
#         except IndexError:
#             raise ValueError
#         dh = key.dh
#         dh.receive_any()
#         key.key = dh.get_secret()
#         key.keyname = id_
#         print("DH1080 Finish: {} on {} {}".format(target, network, 'with CBC mode' if len(word)>5 and word[5]=='CBC' else ''))
#         print("Key set to %r" % (key.key,))
#         ## save key storage
#         self.save_db()
#         return xchat.EAT_ALL
#
#     ## handle topic server message
#     def server_332_topic(self, word, word_eol, userdata):
#         ## check if allready processing
#         if self.__chk_proc():
#             return xchat.EAT_NONE
#         server, cmd, nick, channel, topic = word[0], word[1], word[2], word[3], word_eol[4]
#         ## check if topic is crypted
#         if not topic.startswith(':+OK ') and not topic.startswith(':mcps '):
#             return xchat.EAT_NONE
#         id_ = self.get_id(nick=channel)
#         ## look for a key
#         key = self.find_key(id_,create=SecretKey(None))
#         ## if no key exit
#         if not key.key:
#             return xchat.EAT_NONE
#         ## decrypt
#         topic = self.decrypt(key, topic[1:])
#         if not topic:
#             return xchat.EAT_NONE
#         ## lock the target
#         self.__lock_proc(True)
#         ## send the message to xchat
#         xchat.command('RECV %s %s %s %s :%s' % (server, cmd, nick, channel, topic.replace("\x00","")))
#         ## release the lock
#         self.__lock_proc(False)
#         return xchat.EAT_ALL
#
#     ## trace nick changes
#     def nick_trace(self, word, word_eol, userdata):
#         old, new = word[0], word[1]
#         ## create id's for old and new nick
#         oldid,newid = (self.get_id(nick=old),self.get_id(nick=new))
#         target, network = newid
#         networkmap = self.__TargetMap.get(network,None)
#         if not networkmap:
#             networkmap = {}
#             self.__TargetMap[network] = networkmap
#         key = self.__KeyMap.get(oldid,None)
#         if not key:
#             lastaxx,key = networkmap.get(old,(-1,None))
#         if key:
#             ## make the new nick the entry the old
#             networkmap[new] = (int(time.time()),key)
#             try:
#                 del networkmap[old]
#             except KeyError:
#                 pass
#             ## save key storage
#             self.save_db()
#         return xchat.EAT_NONE


config = Config.load()
hexfish_commands = HexFishCommands()
hexfish = None
