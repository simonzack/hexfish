
import sys

try:
    import xchat
except ImportError:
    xchat = None
    print('XChat not active.')
    sys.exit(1)
