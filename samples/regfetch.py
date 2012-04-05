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

import sys
from Registry import Registry

def usage():
    return "  USAGE:\n\t%s <Windows Registry file> <Registry key path> <Registry Value>" % sys.argv[0]

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])
    key = registry.open(sys.argv[2])
    if sys.argv[3] == "default":
        sys.argv[3] = "(default)"

    value = key.value(sys.argv[3])


    sys.stdout.write(str(value.value()))
