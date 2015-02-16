from __future__ import print_function
from __future__ import unicode_literals

import sys
from Registry import *


def format_total_keys(total_keys):
    return "total_keys|{total_keys}".format(total_keys=total_keys)


def format_total_values(total_values):
    return "total_values|{total_values}".format(total_values=total_values)


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


class RegistryExplorer(object):
    def __init__(self, root):
        self._root = root

    def handle_pre(self):
        pass

    def handle_key(self, key):
        raise NotImplementedException()

    def handle_value(self, key, value):
        raise NotImplementedException()

    def handle_post(self):
        pass

    def _rec(self, key):
        self.handle_key(key)
        for value in key.values():
            self.handle_value(key, value)
        map(self._rec, key.subkeys())

    def go(self):
        self.handle_pre()
        self._rec(self._root)
        self.handle_post()


class TestDumper(RegistryExplorer):
    def __init__(self, *args, **kwargs):
        super(TestDumper, self).__init__(*args, **kwargs)
        self._key_count = 0
        self._value_count = 0

    def handle_key(self, key):
        self._key_count += 1
        try:
            print(format_key(key))
        except UnicodeEncodeError:
            pass
        except UnicodeDecodeError:
            pass

    def handle_value(self, key, value):
        self._value_count += 1
        try:
            print(format_value(key, value))
        except UnicodeEncodeError:
            pass
        except UnicodeDecodeError:
            pass


    def handle_post(self):
        print(format_total_keys(self._key_count))
        print(format_total_values(self._value_count))


reg = Registry.Registry(sys.argv[1])
TestDumper(reg.root()).go()
