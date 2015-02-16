from __future__ import print_function
from __future__ import unicode_literals

import sys
from Registry import *

def rec(key):

    if key._nkrecord.has_classname():
        print("%s : %s" % (key.path(), key._nkrecord.classname()))

    for subkey in key.subkeys():
        rec(subkey)

reg = Registry.Registry(sys.argv[1])
rec(reg.root())

