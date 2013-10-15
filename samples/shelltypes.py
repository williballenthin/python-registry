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

import re, sys, datetime, time
from Registry import Registry

def get_shellbags(registry):
    shellbags = []
    # TODO try both Shell and ShellNoRoam
    try:
        # Windows XP NTUSER.DAT location
        windows = registry.open("Software\\Microsoft\\Windows\\ShellNoRoam")
    except Registry.RegistryKeyNotFoundException:
        try:
            # Windows 7 UsrClass.dat location
            windows = registry.open("Local Settings\\Software\\Microsoft\\Windows\\Shell")
        except Registry.RegistryKeyNotFoundException:
            print("Unable to find shellbag key.")
            sys.exit(-1)
    bagmru = windows.subkey("BagMRU")

    def shellbag_rec(key, bag_prefix):
        for value in key.values():
            if not re.match("\d+", value.name()):
                continue
            mru_type = ord(value.value()[2:3])
            print("%s %s" % (hex(mru_type), bag_prefix + "\\" + value.name()))

            shellbag_rec(key.subkey(value.name()), bag_prefix + "\\" + value.name())

    shellbag_rec(bagmru, "")

def usage():
    return "  USAGE:\n\t%s <Windows Registry file>" % sys.argv[0]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(usage())
        sys.exit(-1)

    get_shellbags(Registry.Registry(sys.argv[1]))
