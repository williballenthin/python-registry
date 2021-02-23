#!/usr/bin/python

#    This file is part of python-registry.
#
#   Copyright 2011 Will Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import print_function
from __future__ import unicode_literals

import os
import sys
from Registry import Registry


def usage():
    return "  USAGE:\n\t%s <Windows Registry file> <Registry key path> [<Registry Value>]" % sys.argv[0]


if __name__ == '__main__':
    if len(sys.argv) != 4 and len(sys.argv) != 3:
        print(usage())
        sys.exit(-1)

    # this is wild, on Windows, redirection of the stream may be in text mode
    #   so line ending characters may quietly be inserted into binary data!
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    registry = Registry.Registry(sys.argv[1])

    try:
        if sys.argv[2].startswith(registry.root().name()):
            key = registry.open(sys.argv[2].partition("\\")[2])
        else:
            key = registry.open(sys.argv[2])
    except Registry.RegistryKeyNotFoundException:
        print("Specified key not found")
        sys.exit(-1)

    if len(sys.argv) == 4:
        if sys.argv[3] == "default":
            sys.argv[3] = "(default)"

        value = key.value(sys.argv[3]).value()
        if isinstance(value, str):
            sys.stdout.write(value)
        elif isinstance(value, bytes):
            sys.stdout.buffer.write(value)
        else:
            raise ValueError("unexpected value type: " + str(type(value)))
    if len(sys.argv) == 3:
        print("Subkeys")
        for subkey in key.subkeys():
            print("  - {}".format(subkey.name()))

        print("Values")
        for value in key.values():
            print("  - {}".format(value.name()))

