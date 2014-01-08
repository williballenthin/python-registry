from __future__ import print_function
from __future__ import unicode_literals

import sys
from Registry import *

def rec(key):
    print("KEY|" + key.path())
    for value in key.values():
        print("VALUE|" + key.path() + "|" + value.name())
    for subkey in key.subkeys():
        rec(subkey)

reg = Registry.Registry(sys.argv[1])
rec(reg.root())

