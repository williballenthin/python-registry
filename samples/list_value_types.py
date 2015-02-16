from __future__ import print_function
from __future__ import unicode_literals

import sys
from Registry import *

def rec(key):
    for value in key.values():
        print("%s : %s : %s" % (key.path(), value.name(), value.value_type_str()))

    for subkey in key.subkeys():
        rec(subkey)

reg = Registry.Registry(sys.argv[1])
rec(reg.root())

