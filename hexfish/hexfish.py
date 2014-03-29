#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from .blowcrypt import BlowCrypt, BlowCryptCBC
from .mircrypt import MirCrypt, MirCryptCBC
from .dh1080 import DH1080
from .compat import xchat
from .text import add_color

__module_name__ = 'hexfish'
__module_version__ = '4.21'
__module_description__ = 'fish encryption in pure python'
is_beta = False

commands = []

def register_command(cls):
    cls.name


class HexChatCommand:
    def _main(self, argv):
        try:
            self.main(argv)
        except ValueError as e:
            print(add_color('dred', 'fish error: ' + str(e)))

    def main(self, argv):
        raise NotImplementedError


class HexFish:
    def __init__(self):
        print("%sFishcrypt Version %s %s\003" % (COLOR['blue'],__module_version__,is_beta))
        self.active = True
        self.__KeyMap = {}
        self.__TargetMap = {}
        self.__lockMAP = {}

        self.status = {
            'CHKPW': None,
            'DBPASSWD' : None,
            'CRYPTDB' : False,
            'LOADED' : True
        }
        self.__hooks = []
        self.__hooks.append(xchat.hook_command('SETKEY', self.set_key, help='set a new key for a nick or channel /SETKEY <nick>/#chan [new_key]'))
        self.__hooks.append(xchat.hook_command('KEYX', self.key_exchange, help='exchange a new pub key, /KEYX <nick>'))
        self.__hooks.append(xchat.hook_command('KEY', self.show_key, help='list key of a nick or channel or all (*), /KEY [nick/#chan/*]' ))
        self.__hooks.append(xchat.hook_command('DELKEY', self.del_key, help='remove key, /DELKEY <nick>/#chan/*'))
        self.__hooks.append(xchat.hook_command('CBCMODE', self.set_cbc, help='set or shows cbc mode for (current) channel/nick , /CBCMODE [<nick>] <0|1>'))
        self.__hooks.append(xchat.hook_command('PROTECTKEY', self.set_protect, help='sets or shows key protection mode for (current) nick, /PROTECTKEY [<nick>] <0|1>'))
        self.__hooks.append(xchat.hook_command('ENCRYPT', self.set_act, help='set or shows encryption on for (current) channel/nick , /ENCRYPT [<nick>] <0|1>'))

        self.__hooks.append(xchat.hook_command('PRNCRYPT', self.prn_crypt, help='print msg encrpyted localy , /PRNCRYPT <msg>'))
        self.__hooks.append(xchat.hook_command('PRNDECRYPT', self.prn_decrypt, help='print msg decrpyted localy , /PRNDECRYPT <msg>'))

        ## check for password sets
        self.__hooks.append(xchat.hook_command('SET',self.settings))
        self.__hooks.append(xchat.hook_command('DBPASS',self.set_dbpass))
        self.__hooks.append(xchat.hook_command('DBLOAD',self.set_dbload))

        self.__hooks.append(xchat.hook_command('HELP',self.get_help))

        self.__hooks.append(xchat.hook_command('', self.out_message))
        self.__hooks.append(xchat.hook_command('ME+', self.out_message_cmd))
        self.__hooks.append(xchat.hook_command('MSG', self.out_message_cmd))
        self.__hooks.append(xchat.hook_command('MSG+', self.out_message_force))
        self.__hooks.append(xchat.hook_command('NOTICE', self.out_message_cmd))
        self.__hooks.append(xchat.hook_command('NOTICE+', self.out_message_force))

        self.__hooks.append(xchat.hook_server('notice', self.on_notice,priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_server('332', self.server_332_topic,priority=xchat.PRI_HIGHEST))

        self.__hooks.append(xchat.hook_print('Notice Send',self.on_notice_send, 'Notice',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Change Nick', self.nick_trace))
        self.__hooks.append(xchat.hook_print('Channel Action', self.in_message, 'Channel Action',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Action to Dialog', self.in_message, 'Private Action to Dialog',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Action ', self.in_message, 'Private Action',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Channel Message', self.in_message, 'Channel Message',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Message to Dialog', self.in_message, 'Private Message to Dialog',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Message', self.in_message, 'Private Message',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_unload(self.__destroy))
        self.load_db()

    def __destroy(self, userdata):
        for hook in self.__hooks:
            xchat.unhook(hook)
        del self

    def __del__(self):
        print("\00311fishcrypt.py successfully unloaded")

    def get_help(self, word, word_eol, userdata):
        if len(word) < 2:
            print("\n\0033 For fishcrypt.py help type /HELP FISHCRYPT")
            return xchat.EAT_NONE
        if word[1].upper() == "FISHCRYPT":
            print("")
            print("\002\0032 ****  fishcrypt.py Version: %s %s ****" % (__module_version__, is_beta))
            print("\n")
            print(" \002\00314***************** Fishcrypt Help ********************")
            print(" -----------------------------------------------------")
            print("/MSG+ \00314send crypted msg regardless of /ENCRYPT setting")
            print("/NOTICE+ \00314send crypted notice regardless of /ENCRYPT setting")
            print("/ME+ \00314send crypted CTCP ACTION")
            print("/SETKEY \00314set a new key for a nick or channel")
            print("/KEYX \00314exchange pubkey for dialog")
            print("/KEY \00314show Keys")
            print("/DELKEY \00314delete Keys")
            print("/CBCMODE \00314enable/disable CBC Mode for this Key")
            print("/ENCRYPT \00314enable/disable encryption for this Key")
            print("/PROTECTKEY \00314enable/disable protection for keyx key exchange")
            print("/DBPASS \00314set/change the passphrase for the Key Storage")
            print("/DBLOAD \00314loads the Key Storage")
            print("/PRNDECRYPT \00314decrypts messages localy")
            print("/PRNCRYPT \00314encrypts messages localy")
            print("/SET [fishcrypt] \00314show/set fishcrypt settings")
            return xchat.EAT_ALL

    ## incoming notice received
    def on_notice(self, word, word_eol, userdata):
        ## check if this is not allready processed
        if self.__chk_proc():
            return xchat.EAT_NONE

        ## check if DH Key Exchange
        if word_eol[3].startswith(':DH1080_FINISH'):
            return self.dh1080_finish(word, word_eol, userdata)
        elif word_eol[3].startswith(':DH1080_INIT'):
            return self.dh1080_init(word, word_eol, userdata)

        ## check for encrypted Notice
        elif word_eol[3].startswith('::+OK ') or word_eol[3].startswith('::mcps '):

            ## rewrite data to pass to default inMessage function
            ## change full ident to nick only
            nick = self.get_nick(word[0])
            target = word[2]
            speaker = nick
            ## strip :: from message
            message = word_eol[3][2:]
            if target.startswith("#"):
                id_ = self.get_id()
                speaker = "## %s" % speaker
            else:
                id_ = self.get_id(nick=nick)
            #print "DEBUG(crypt): key: %r word: %r" % (id,word,)
            key = self.find_key(id_)
            ## if no key found exit
            if not key:
                return xchat.EAT_NONE

            ## decrypt the message
            try:
                sndmessage = self.decrypt(key,message)
            except:
                sndmessage = None
            is_cbc=0
            if message.startswith("+OK *"):
                is_cbc=1
            failcol = ""

            ## if decryption was possible check for invalid chars
            if sndmessage:
                try:
                    message = sndmessage
                    ## mark nick for encrypted msgg
                    speaker = "%s %s" % ("°"*(1+is_cbc),speaker)
                except UnicodeError:
                    try:
                        message = str(sndmessage,encoding='iso8859-1',errors='ignore').encode('UTF8')
                        ## mark nick for encrypted msgg
                        speaker = "%s %s" % ("°"*(1+is_cbc),speaker)
                    except:
                        raise
                    ## send the message to local xchat
                    #self.emit_print(userdata,speaker,message)
                    #return xchat.EAT_XCHAT
                except:
                    ## mark nick with a question mark
                    speaker = "?%s" % speaker
                    failcol = "\003"
            else:
                failcol = "\003"
            ## mark the message with \003, it failed to be processed and there for the \003+OK  will no longer be excepted as encrypted so it wont loop
            self.emit_print(userdata,speaker,"%s%s" % (failcol,message))
            return xchat.EAT_XCHAT
#            return self.inMessage([nick,msg], ["%s %s" % (nick,msg),msg], userdata)

        ## ignore everything else
        else:
            #print "DEBUG: %r %r %r" % (word, word_eol, userdata)
            return xchat.EAT_NONE

    ## local notice send messages
    def on_notice_send(self, word, word_eol, userdata):
        ## get current nick
        target = xchat.get_context().get_info('nick')
        #print "DEBUG_notice_send: %r - %r - %r %r" % (word,word_eol,userdata,nick)

        ## check if this is not allready processed
        if self.__chk_proc(target=target):
            return xchat.EAT_NONE

        ## get the speakers nick only from full ident
        speaker = self.get_nick(word[0])

        ## strip first : from notice
        message = word_eol[1][1:]
        if message.startswith('+OK ') or message.startswith('mcps '):
            ## get the key id from the speaker
            id_ = self.get_id(nick=speaker)
            key = self.find_key(id_)

            ## if no key available for the speaker exit
            if not key:
                return xchat.EAT_NONE

            ## decrypt the message
            sndmessage = self.decrypt(key,message)
            is_cbc = 0
            if message.startswith("+OK *"):
                is_cbc = 1
                if not target.startswith("#"):
                    ## if we receive a messge with CBC enabled we asume the partner can also except it so activate it
                    key.cbc_mode = True

            ## if decryption was possible check for invalid chars

            if sndmessage:
                try:
                    message = sndmessage
                    ## mark nick for encrypted msgg
                    speaker = "%s %s" % ("°"*(1+is_cbc),speaker)
                except:
                    ## mark nick with a question mark
                    speaker = "?%s" % speaker
                    ## send original message because invalid chars
                    message = message

            ## send the message back to incoming notice but with locked target status so it will not be processed again
            self.emit_print("Notice Send",speaker,message,target=target)
            return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    ## incoming messages
    def in_message(self, word, word_eol, userdata):
        ## if message is allready processed ignore
        if self.__chk_proc() or len(word_eol) < 2:
            return xchat.EAT_PLUGIN

        speaker = word[0]
        message = word_eol[1]
        #print "DEBUG(INMsg): %r - %r - %r" % (word,word_eol,userdata)
        # if there is mode char, remove it from the message
        if len(word_eol) >= 3:
            #message = message[ : -(len(word_eol[2]) + 1)]
            message = message[:-2]

        ## check if message is crypted
        if message.startswith('+OK ') or message.startswith('mcps '):
            target = None
            if userdata == "Private Message":
                target = speaker
            id_ = self.get_id(nick=target)
            target,network = id_
            key = self.find_key(id_)

            ## if no key found exit
            if not key:
                return xchat.EAT_NONE

            ## decrypt the message
            try:
                sndmessage = self.decrypt(key,message)
            except:
                sndmessage = None
            is_cbc=0
            if message.startswith("+OK *"):
                is_cbc=1
                if not target.startswith("#"):
                    ## if we receive a messge with CBC enabled we asume the partner can also except it so activate it
                    key.cbc_mode = True

            failcol = ""

            ## if decryption was possible check for invalid chars
            if sndmessage:
                try:
                    message = sndmessage
                    ## mark nick for encrypted msgg
                    speaker = "%s %s" % ("°"*(1+is_cbc),speaker)
                except UnicodeError:
                    try:
                        message = str(sndmessage,encoding='iso8859-1',errors='ignore').encode('UTF8')
                        ## mark nick for encrypted msgg
                        speaker = "%s %s" % ("°"*(1+is_cbc),speaker)
                    except:
                        raise
                    ## send the message to local xchat
                    #self.emit_print(userdata,speaker,message)
                    #return xchat.EAT_XCHAT
                except:
                    ## mark nick with a question mark
                    speaker = "?%s" % speaker
                    failcol = "\003"
            else:
                failcol = "\003"
            ## mark the message with \003, it failed to be processed and there for the \003+OK  will no longer be excepted as encrypted so it wont loop
            self.emit_print(userdata,speaker,"%s%s" % (failcol,message))
            return xchat.EAT_ALL

        return xchat.EAT_NONE

    def decrypt(self, key, msg):
        ## check for CBC
        if 3 <= msg.find(' *') <= 4:
            decrypt_clz = BlowfishCBC
            decrypt_func = mircryption_cbc_unpack
        else:
            decrypt_clz = Blowfish
            decrypt_func = blowcrypt_unpack

        b = decrypt_clz(key.key.encode())
        try:
            ret = decrypt_func(msg, b)
        except MalformedError:
            try:
                cut = (len(msg) -4)%12
                if cut > 0:
                    msg = msg[:cut *-1]
                    ret = "%s%s" % ( decrypt_func(msg, b), " \0038<<incomplete>>" * (cut>0))
                else:
                    #print "Error Malformed %r" % len(msg)
                    ret = None
            except MalformedError:
                #print "Error2 Malformed %r" % len(msg)
                ret = None
        except:
            print("Decrypt ERROR")
            ret = None
        return ret

    ## mark outgoing message being  prefixed with a command like /notice /msg ...
    def out_message_cmd(self, word, word_eol, userdata):
        return self.out_message(word, word_eol, userdata,command=True)

    ## mark outgoing message being prefixed with a command that enforces encryption like /notice+ /msg+
    def out_message_force(self, word, word_eol, userdata):
        return self.out_message(word, word_eol, userdata, force=True,command=True)

    ## the outgoing messages will be proccesed herre
    def out_message(self, word, word_eol, userdata,force=False,command=False):

        ## check if allready processed
        if self.__chk_proc():
            return xchat.EAT_NONE

        ## get the id
        id_ = self.get_id()
        target,network = id_
        ## check if message is prefixed wit a command like /msg /notice
        action = False
        if command:

            if len(word) < (word[0].upper().startswith("ME") and 2 or 3):
                print("Usage: %s <nick/channel> <message>, sends a %s.%s are a type of message that should be auto reacted to" % (word[0],word[0],word[0]))
                return xchat.EAT_ALL
            ## notice and notice+
            if word[0].upper().startswith("NOTICE"):
                command = "NOTICE"
            else:
                command = "PRIVMSG"
            if word[0].upper().startswith("ME"):
                action = True
                message = word_eol[1]
            else:
                ## the target is first parameter after the command, not the current channel
                target = word[1]
                ## change id
                id_ = (target,network)
                ## remove command and target from message
                message = word_eol[2]
        else:
            command = "PRIVMSG"
            message = word_eol[0]

        sendmsg = ''
        ## try to get a key for the target id
        key = self.find_key(id_)

        ## my own nick
        nick = xchat.get_context().get_info('nick')

        #print "DEBUG(outMsg1)(%r) %r : %r %r" % (id,xchat.get_context().get_info('network'),word,nick)

        ## if we don't have a key exit
        if not key:
            return xchat.EAT_NONE

        ## if the key object is there but the key deleted or marked not active...and force is not set by command like /msg+ or /notice+
        if key.key is None or (key.active == False and not force):
            return xchat.EAT_NONE

        ## encrypt message
        maxlen = self.config['MAXMESSAGELENGTH']
        cutmsg = message
        messages = []
        sendmessages = []
        while len(cutmsg) >0:
            sendmessages.append(self.encrypt(key,cutmsg[:maxlen]))
            messages.append(cutmsg[:maxlen])
            cutmsg = cutmsg[maxlen:]
        ## mark the nick with ° for encrypted messages
        nick = "%s %s" % ("°"*(1+key.cbc_mode),nick)

        #print "DEBUG(outMsg2): %r %r %r %r" % (command,message,nick,target)

        for sendmsg in sendmessages:
            ## lock the target
            self.__lock_proc(True)
            ## send the command (PRIVMSG / NOTICE)
            if action:
                sendmsg = "\001ACTION %s\001" % sendmsg
            xchat.command('%s %s :%s' % (command,target, sendmsg))
            ## release the lock
            self.__lock_proc(False)

        for message in messages:
            ## if it is no notice it must be send plaintext to xchat for you
            if command == "PRIVMSG":
                if action:
                    self.emit_print('Channel Action',  nick, message)
                else:
                    target_tab= xchat.find_context(channel=target)
                    if not target_tab and target_tab != xchat.get_context():
                        self.emit_print('Message Send',  "%s %s" % ("°"*(1+key.cbc_mode),target), message)
                    else:
                        self.emit_print('Your Message',  nick, message, to_context=target_tab)
        return xchat.EAT_ALL

    def encrypt(self,key, msg):
        if key.cbc_mode:
            encrypt_clz = BlowfishCBC
            encrypt_func = mircryption_cbc_pack
        else:
            encrypt_clz = Blowfish
            encrypt_func = blowcrypt_pack
        b = encrypt_clz(key.key.encode())
        return encrypt_func(msg, b)

    ## send message to local xchat and lock it
    def emit_print(self,userdata,speaker,message,target=None,to_context=None):
        if not to_context:
            to_context = xchat.get_context()
        if userdata is None:
            ## if userdata is none its possible Notice
            userdata = "Notice"
        if not target:
            ## if no special target for the lock is set, make it the speaker
            target = speaker
        ## lock the processing of that message
        self.__lock_proc(True,target=target)
        ## check for Highlight
        for hl in [xchat.get_info('nick')] + xchat.get_prefs("irc_extra_hilight").split(","):
            if len(hl) >0 and message.find(hl) > -1:
                if userdata == "Channel Message":
                    userdata = "Channel Msg Hilight"
                xchat.command("GUI COLOR 3")
        ## send the message
        to_context.emit_print(userdata,speaker, message.replace('\0',''))
        ## release the lock
        self.__lock_proc(False,target=target)

    ## set or release the lock on the processing to avoid loops
    def __lock_proc(self,state,target=None):
        ctx = xchat.get_context()
        if not target:
            ## if no target set, the current channel is the target
            target = ctx.get_info('channel')
        ## the lock is NETWORK-TARGET
        id_ = "%s-%s" % (ctx.get_info('network'),target)
        self.__lockMAP[id_] = state

    ## check if that message is allready processed to avoid loops
    def __chk_proc(self,target=None):
        ctx = xchat.get_context()
        if not target:
            ## if no target set, the current channel is the target
            target = ctx.get_info('channel')
        id_ = "%s-%s" % (ctx.get_info('network'),target)
        return self.__lockMAP.get(id_,False)

    # get an id from channel name and networkname
    def get_id(self,nick=None):
        ctx = xchat.get_context()
        if nick:
            target = nick
        else:
            target = str(ctx.get_info('channel'))
        ##return the id
        return target, str(ctx.get_info('network')).lower()

    def find_key(self, id_, create=None):
        key = self.__KeyMap.get(id_,None)
        target, network = id_
        networkmap = self.__TargetMap.get(network,None)
        if not networkmap:
            networkmap = {}
            self.__TargetMap[network] = networkmap
        if not key:
            lastaxx,key = networkmap.get(target,(-1,None))
        else:
            for _target,_key in [x for x in networkmap.items() if x[1] == key]:
                if _target != target:
                    del networkmap[_target]
        if not key and create:
            key = create
        if key:
            self.__TargetMap[network][target] = (int(time.time()),key)
        return key

    ## return the nick only
    def get_nick(self,full):
        if full[0] == ':':
            full = full[1:]
        try:
            ret = full[:full.index('!')]
        except ValueError:
            ret  = full
        return ret

    ## print encrypted localy
    def prn_crypt(self, word, word_eol, userdata):
        id_ = self.get_id()
        target, network = id_
        key = self.find_key(id_)
        if len(word_eol) < 2:
            print("usage: /PRNCRYPT <msg to encrypt>")
        else:
            if key:
                print("%s%s" % (COLOR['blue'],self.encrypt(key,word_eol[1])))
            else:
                print("%sNo known Key found for %s" % (COLOR['red'],target,))
        return xchat.EAT_ALL

    ## print decrypted localy
    def prn_decrypt(self, word, word_eol, userdata):
        id_ = self.get_id()
        target, network = id_
        key = self.find_key(id_)
        if len(word_eol) < 2:
            print("usage: /PRNDECRYPT <msg to decrypt>")
        else:
            if key:
                print("%s%s" % (COLOR['blue'],self.decrypt(key,word_eol[1])))
            else:
                print("%sNo known Key found for %s" % (COLOR['red'],target,))
        return xchat.EAT_ALL


    ## manual set a key for a nick or channel
    def set_key(self, word, word_eol, userdata):
        id_ = self.get_id()
        target, network = id_

        ## if more than 2 parameter the nick/channel target is set to para 1 and the key is para 2
        if len(word) > 2:
            target = word[1]
            if target.find("@") > 0:
                target,network = target.split("@",1)
            newkey = word[2]
            id_ = (target,network)
        ## else the current channel/nick is taken as target and the key is para 1
        else:
            newkey = word[1]
        if len(newkey) < 8 or len(newkey) > 56:
            print("Key must be between 8 and 56 chars")
            return xchat.EAT_ALL
        ## get the Keyobject if available or get a new one
        key = self.find_key(id_,create=SecretKey(None,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
        ## set the key
        key.key = newkey
        key.keyname = id_
        ## put it in the key dict
        self.__KeyMap[id_] = key

        print("Key for %s on Network %s set to %r" % ( target,network,newkey))
        ## save the key storage
        self.save_db()
        return xchat.EAT_ALL

    ## delete a key or all
    def del_key(self, word, word_eol, userdata):
        ## don't accept no parameter
        if len(word) <2:
            print("Error: /DELKEY nick|channel|* (* deletes all keys)")
            return xchat.EAT_ALL
        target = word_eol[1]
        ## if target name is * delete all
        if target == "*":
            self.__KeyMap = {}
        else:
            if target.find("@") > 0:
                target,network = target.split("@",1)
                id_ = target,network
            else:
                id_ = self.get_id(nick=target)
                target,network = id_
            ## try to delete the key
            try:
                del self.__KeyMap[id_]
                print("Key for %s on %s deleted" % (target,network))
            except KeyError:
                print("Key %r not found" % (id_,))
        ## save the keystorage
        self.save_db()
        return xchat.EAT_ALL

    ## show either key for current chan/nick or all
    def show_key(self, word, word_eol, userdata):
        ## if no parameter show key for current chan/nick
        if len(word) <2:
            id_ = self.get_id()
        else:
            target = word_eol[1]
            network = ""
            if target.find("@") > 0:
                target,network = target.split("@",1)
                if network.find("*") > -1:
                    network = network[:-1]
            ## if para 1 is * show all keys and there states
            if target.find("*") > -1:
                print(" -------- nick/chan ------- -------- network ------- -ON- -CBC- -PROTECT- -------------------- Key --------------------")
                for id_, keys in self.__KeyMap.items():
                    if id_[0].startswith(target[:-1]) and id_[1].startswith(network):
                        print("  %-26.26s %-22.22s  %2.2s   %3.3s   %5.5s      %s" % (id_[0],id_[1],YESNO(keys.active),YESNO(keys.cbc_mode),YESNO(keys.protect_mode),keys.key))

                return xchat.EAT_ALL
            ## else get the id for the target
            id_ = self.get_id(nick=target)

        ## get the Key
        key = self.find_key(id_)
        if key:
            ## show Key for the specified chan/nick
            print("[ %s ] Key: %s - Active: %s - CBC: %s - PROTECT: %s" % (key,key.key,YESNO(key.active),YESNO(key.cbc_mode),YESNO(key.protect_mode)))
        else:
            print("No Key found")
        return xchat.EAT_ALL

    ## set cbc mode or show the status
    def set_cbc(self, word, word_eol, userdata):
        ## check for parameter
        mode = None
        if len(word) >2:
            # if both specified first is target second is mode on/off
            target = word[1]
            mode = word[2]
        else:
            ## if no target defined target is current chan/nick
            target = None
            if len(word) >1:
                ## if one parameter set mode to it else show only
                mode = word[1]

        id_ = self.get_id(nick=target)
        target,network = id_
        ## check if there is a key
        key = self.find_key(id_)
        if not key:
            print("No Key found for %r" % (target,))
        else:
            ## if no parameter show only status
            if len(word) == 1:
                print("CBC Mode is %s" % ((key.cbc_mode and "on" or "off"),))
            else:
                ## set cbc mode to on/off
                key.cbc_mode = bool(mode in ONMODES)
                print("set CBC Mode for %s to %s" % (target,(key.cbc_mode == True and "on") or "off"))
                ## save key storage
                self.save_db()
        return xchat.EAT_ALL

    ## set key protection mode or show the status
    def set_protect(self, word, word_eol, userdata):
        ## check for parameter
        mode = None
        if len(word) >2:
            # if both specified first is target second is mode on/off
            target = word[1]
            mode = word[2]
        else:
            ## if no target defined target is current nick, channel is not allowed/possible yet
            target = None
            if len(word) >1:
                ## if one parameter set mode to it else show only
                mode = word[1]

        id_ = self.get_id(nick=target)
        target,network = id_
        if "#" in target:
            print("We don't make channel protection. Sorry!")
            return xchat.EAT_ALL

        key = self.find_key(id_)
        ## check if there is a key
        if not key:
            print("No Key found for %r" % (target,))
        else:
            ## if no parameter show only status
            if len(word) == 1:
                print("KEY Protection is %s" % ((key.protect_mode and "on" or "off"),))
            else:
                ## set KEY Protection mode to on/off
                key.protect_mode = bool(mode in ONMODES)
                print("set KEY Protection for %s to %s" % (target,(key.protect_mode == True and "on") or "off"))
                ## save key storage
                self.save_db()
        return xchat.EAT_ALL


    ## activate/deaktivate encryption für chan/nick
    def set_act(self, word, word_eol, userdata):
        ## if two parameter first is target second is mode on/off
        mode = None
        if len(word) >2:
            target = word[1]
            mode = word[2]
        else:
            ## target is current chan/nick
            target = None
            if len(word) >1:
                ## if one parameter set mode to on/off
                mode = word[1]

        id_ = self.get_id(nick=target)
        target,network = id_
        key = self.find_key(id_)
        ## key not found
        if not key:
            print("No Key found for %r" % (target,))
        else:
            if len(word) == 1:
                ## show only
                print("Encryption is %s" % ((key.active and "on" or "off"),))
            else:
                ## set mode to on/off
                key.active = bool(mode in ONMODES)
                print("set Encryption for %s to %s" % (target,(key.active == True and "on") or "off"))
                ## save key storage
                self.save_db()
        return xchat.EAT_ALL

    ## start the DH1080 Key Exchange
    def key_exchange(self, word, word_eol, userdata):
        id_ = self.get_id()
        target,network = id_
        if len(word) >1:
            target = word[1]
            id_ = (target,network)

        ## XXX chan notice - what should happen when keyx is send to channel trillian seems to accept it and send me a key --
        if target.startswith("#"):
            print("Channel Exchange not implemented")
            return xchat.EAT_ALL

        ## create DH
        dh = DH1080()

        self.__KeyMap[id_] = self.find_key(id_,create=SecretKey(dh,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
        self.__KeyMap[id_].keyname = id_
        self.__KeyMap[id_].dh = dh

        ## lock the target
        self.__lock_proc(True)
        ## send key with notice to target
        xchat.command('NOTICE {} {}'.format(target, dh.send_request(self.config['DEFAULTCBC'])))
        ## release the lock
        self.__lock_proc(False)

        ## save the key storage
        self.save_db()
        return xchat.EAT_ALL

    ## Answer to KeyExchange
    def dh1080_init(self, word, word_eol, userdata):
        id_ = self.get_id(nick=self.get_nick(word[0]))
        target,network = id_
        message = word_eol[3]
        key = self.find_key(id_,create=SecretKey(None,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))

        ## Protection against a new key if "/PROTECTKEY" is on for nick
        if key.protect_mode:
            print("%sKEYPROTECTION: %s on %s" % (COLOR['red'],target,network))
            xchat.command("notice %s %s KEYPROTECTION:%s %s" % (target,self.config['PLAINTEXTMARKER'],COLOR['red'],target))
            return xchat.EAT_ALL

        ## Stealth Check
        if self.config['FISHSTEALTH']:
            print("%sSTEALTHMODE: %s tried a keyexchange on %s" % (COLOR['green'],target,network))
            return xchat.EAT_ALL

        dh = DH1080()
        dh.receive_any(message[1:])
        key.key = dh.get_secret()
        key.keyname = id_

        ## lock the target
        self.__lock_proc(True)
        ## send key with notice to target
        xchat.command('NOTICE {} {}'.format(target, dh.send_response()))

        ## release the lock
        self.__lock_proc(False)
        self.__KeyMap[id_] = key
        print("DH1080 Init: {} on {} {}".format(target, network, 'with CBC mode' if len(word)>5 and word[5]=='CBC' else ''))
        print("Key set to %r" % (key.key,))
        ## save key storage
        self.save_db()
        return xchat.EAT_ALL

    ## Answer from targets init
    def dh1080_finish(self, word, word_eol, userdata):
        id_ = self.get_id(nick=self.get_nick(word[0]))
        target,network = id_
        ## XXX if not explicit send to the Target the received key is discarded - chan exchange
        if id_ not in self.__KeyMap:
            print("Invalid DH1080 Received from %s on %s" % (target,network))
            return xchat.EAT_NONE
        key = self.__KeyMap[id_]
        try:
            message = "%s %s" % (word[3],word[4])
        except IndexError:
            raise MalformedError
        dh = key.dh
        dh.receive_any()
        key.key = dh.get_secret()
        key.keyname = id_
        print("DH1080 Finish: {} on {} {}".format(target, network, 'with CBC mode' if len(word)>5 and word[5]=='CBC' else ''))
        print("Key set to %r" % (key.key,))
        ## save key storage
        self.save_db()
        return xchat.EAT_ALL

    ## handle topic server message
    def server_332_topic(self, word, word_eol, userdata):
        ## check if allready processing
        if self.__chk_proc():
            return xchat.EAT_NONE
        server, cmd, nick, channel, topic = word[0], word[1], word[2], word[3], word_eol[4]
        ## check if topic is crypted
        if not topic.startswith(':+OK ') and not topic.startswith(':mcps '):
            return xchat.EAT_NONE
        id_ = self.get_id(nick=channel)
        ## look for a key
        key = self.find_key(id_,create=SecretKey(None))
        ## if no key exit
        if not key.key:
            return xchat.EAT_NONE
        ## decrypt
        topic = self.decrypt(key, topic[1:])
        if not topic:
            return xchat.EAT_NONE
        ## lock the target
        self.__lock_proc(True)
        ## send the message to xchat
        xchat.command('RECV %s %s %s %s :%s' % (server, cmd, nick, channel, topic.replace("\x00","")))
        ## release the lock
        self.__lock_proc(False)
        return xchat.EAT_ALL

    ## trace nick changes
    def nick_trace(self, word, word_eol, userdata):
        old, new = word[0], word[1]
        ## create id's for old and new nick
        oldid,newid = (self.get_id(nick=old),self.get_id(nick=new))
        target, network = newid
        networkmap = self.__TargetMap.get(network,None)
        if not networkmap:
            networkmap = {}
            self.__TargetMap[network] = networkmap
        key = self.__KeyMap.get(oldid,None)
        if not key:
            lastaxx,key = networkmap.get(old,(-1,None))
        if key:
            ## make the new nick the entry the old
            networkmap[new] = (int(time.time()),key)
            try:
                del networkmap[old]
            except KeyError:
                pass
            ## save key storage
            self.save_db()
        return xchat.EAT_NONE


load_obj = HexFish()
