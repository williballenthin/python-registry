#!/usr/bin/python

import sys
from Registry import *

items = []

def rec(key):
    items.append((key.timestamp(), key.path()))
    for subkey in key.subkeys():
        rec(subkey)

for path in sys.argv[1:]: 
    reg = Registry.Registry(path)
    rec(reg.root())

for i in sorted(items, key=lambda x: x[0]):
    print "%s\t%s" % i

