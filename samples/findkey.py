#  find all registry values with the specified string
#  python findkey.py <registry file> <needle>
#

import sys
from Registry import *

def rec(key, depth, needle):
    for value in key.values():
        try:
            if needle in str(value.value()):
                print key.path() + "  " + value.name()
        except UnicodeEncodeError:
            pass
            
    for subkey in key.subkeys():
        rec(subkey, depth + 1, needle)

reg = Registry.Registry(sys.argv[1])
if len(sys.argv) == 3:
    needle = sys.argv[2]
else:
    needle = ""
rec(reg.root(), 0, needle)

