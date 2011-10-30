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
#
#   Find all Registry paths, value names, and values that
#   contain the given string.
#
#   python findkey.py <registry file> <needle>
#

import sys
from Registry import Registry

paths = []
value_names = []
values = []

def rec(key, depth, needle):
    for value in key.values():
        if needle in value.name():
            value_names.append((key.path(), value.name()))
            sys.stdout.write("n")
            sys.stdout.flush()
        try:
            if needle in str(value.value()):
                values.append((key.path(), value.name()))
                sys.stdout.write("v")
                sys.stdout.flush()
        except UnicodeEncodeError:
            pass
            
    for subkey in key.subkeys():
        if needle in subkey.name():
            paths.append(subkey.path())
            sys.stdout.write("p")
            sys.stdout.flush()
        rec(subkey, depth + 1, needle)


reg = Registry.Registry(sys.argv[1])
if len(sys.argv) == 3:
    needle = sys.argv[2]
else:
    needle = ""
rec(reg.root(), 0, needle)
print ""

print "[Paths]"
for path in paths:
    print "  - %s" % (path)
if len(paths) == 0:
    print "  (none)"
print ""

print "[Value Names]"
for pair in value_names:
    print "  - %s : %s" % (pair[0], pair[1])
if len(value_names) == 0:
    print "  (none)"
print ""

print "[Values]"
for pair in values:
    print "  - %s : %s" % (pair[0], pair[1])
if len(values) == 0:
    print "  (none)"
print ""
