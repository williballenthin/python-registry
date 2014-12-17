from __future__ import print_function
from __future__ import unicode_literals

import sys
from Registry import *


def format_key(key):
    return "key|{path}|{ts}".format(
            path=key.path(),
            ts=key.timestamp().isoformat(chr(ord("T"))) + "Z")


def format_value(key, value):
    try:
        h = " ".join(["%02X" % (ord(c)) for c in value.raw_data()])
    except RegistryParse.UnknownTypeException:
        h = "UNKNOWN_TYPE_SO_UNKNOWN_DATA"
    return "value|{path}|{name}|{type}|{hex}".format(
            path=key.path(),
            name=value.name(),
            type=value.value_type(),
            hex=h)


def handle_key(key):
    print(format_key(key))


def handle_value(key, value):
    print(format_value(key, value))


def rec(key, depth=0):
    handle_key(key)
    for value in key.values():
        handle_value(key, value)
    map(rec, key.subkeys())


reg = Registry.Registry(sys.argv[1])
rec(reg.root())

