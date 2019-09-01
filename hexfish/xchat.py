'''
Placeholder file for unit tests.
'''

import os

PRI_HIGHEST = None


def get_info(name):
    if name == 'configdir':
        return os.getcwd()


def hook_command(*args, **kwargs):
    pass


def hook_print(*args, **kwargs):
    pass


def hook_server(*args, **kwargs):
    pass


def hook_unload(*args, **kwargs):
    pass


def unhook(*args, **kwargs):
    pass
