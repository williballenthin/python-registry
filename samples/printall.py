from __future__ import print_function
from __future__ import unicode_literals

import sys
from Registry import *

def rec(key, depth=0):
    print("\t" * depth + key.path())
    for subkey in key.subkeys():
        rec(subkey, depth + 1)

reg = Registry.Registry(sys.argv[1])
rec(reg.root())

