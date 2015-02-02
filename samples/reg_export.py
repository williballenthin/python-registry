#!/usr/bin/python

#    This file is part of python-registry.
#
#   Copyright 2015 Willi Ballenthin <william.ballenthin@mandiant.com>
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

import sys
from Registry import Registry

stdout = sys.stdout
if hasattr(stdout, 'buffer'):
    stdout = stdout.buffer

def usage():
    return "  USAGE:\n\t%s <Windows Registry file> <Hive prefix> <Registry key path> [<Registry Value>]" % sys.argv[0]



def reg_format_header():
    """
    @rtype: byte string
    """
    return u"\ufeffWindows Registry Editor Version 5.00\r\n\r\n".encode("utf-16le")


def reg_format_value_sz(value):
    """
    @rtype: str
    """
    return "\"{value}\"".format(value=value.value())


def reg_format_value_dword(value):
    """
    @rtype: str
    """
    return "dword:%08x" % (value.value())


def reg_format_value_bin(value):
    """
    result should look like the following (after the '='):
     "ProductLocalizedName"=hex:40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,\
       6d,00,46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,\
       00,77,00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,\
       45,00,70,00,70,00,4d,00,61,00,6e,00,69,00,66,00,65,00,73,00,74,00,2e,00,64,\
       00,6c,00,6c,00,2c,00,2d,00,31,00,30,00,30,00,30,00,00,00

    so we:
      - format into one big line of hex
      - search for places to split, at about 80 chars or less
      - split, with the former receiving a backslash, and the latter getting the
         prefixed whitespace

    if the type of value is RegBin, then we use the type prefix "hex:",
    otherwise, the type prefix is "hex(%d):" where %d is the value_type constant.
    eg. RegExpandSZ is "hex(3)"

    @rtype: str
    """
    ret = []

    s = ",".join(["%02x" % (ord(c)) for c in value.value()])

    if value.value_type() == Registry.RegBin:
        s = "hex:" + s
    else:
        s = "hex(%d):" % (value.value_type()) + s

    # there might be an off by one error in here somewhere...
    name_len = len(value.name()) + 2 + 1  # name + 2 * '"' + '='
    split_index = 80 - name_len
    while len(s) > 0:
        if len(s) > split_index:
            # split on a comma
            while s[split_index] != ",":
                split_index -= 1
            ret.append(s[:split_index + 1] + "\\")
            s = "  " + s[split_index + 1:]
        else:
            ret.append(s)
            s = ""
        split_index = 80

    return "\r\n".join(ret)


def reg_format_value(value):
    return {
        Registry.RegSZ: reg_format_value_sz,
        Registry.RegExpandSZ: reg_format_value_bin,
        Registry.RegBin: reg_format_value_bin,
        Registry.RegDWord: reg_format_value_dword,
    }[value.value_type()](value)


def reg_format_key_values(registry, prefix, key, values):
    """
    @rtype: byte string
    """
    ret = []
    path = key.path().partition("\\")[2]  # remove root key name ("$$$PROTO_HIV")
    ret.append(u"[{prefix}\{path}]".format(prefix=prefix, path=path))
    for value in values:
        ret.append("\"{name}\"={value}".format(name=value.name(),
                                               value=reg_format_value(value)))
    ret.append("\r\n")
    return u"\r\n".join(ret).encode("utf-16le")


def main(hive, prefix, keyname, *valuenames):
    """
    @param prefix: something like "HKEY_LOCAL_MACHINE" to prepend to formatted key names.
    """
    registry = Registry.Registry(hive)

    key = None
    try:
        if keyname.startswith(registry.root().name()):
            key = registry.open(keyname.partition("\\")[2])
        else:
            key = registry.open(keyname)
    except Registry.RegistryKeyNotFoundException:
        print("Error: Specified key not found")
        sys.exit(-1)

    values = []
    if len(valuenames) != 0:
        for valuename in valuenames:
            if valuename == "default":
                valuename = "(default)"

            values.append(key.value(valuename))
    else:
        values = [v for v in key.values()]

    stdout.write(reg_format_header())
    stdout.write(reg_format_key_values(registry, prefix, key, values))


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(usage())
        sys.exit(-1)

    main(*sys.argv[1:])

