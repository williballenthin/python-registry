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

import sys
from Registry import Registry


def usage():
    return "  USAGE:\n\t%s <Windows Registry file> <Registry key path>" % sys.argv[0]


def main():
    if len(sys.argv) != 2:
        print(usage())
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])
    select = registry.open("Select")
    current = select.value("Current").value()
    services = registry.open("ControlSet00%d\\Services" % (current))
    for service in services.subkeys():
        try:
            display_name = service.value("DisplayName").value()
        except:
            display_name = "???"

        try:
            description = service.value("Description").value()
        except:
            description = "???"

        try:
            image_path = service.value("ImagePath").value()
        except:
            image_path = "???"

        try:
            dll = service.subkey("Parameters").value("ServiceDll").value()
        except:
            dll = "???"
        print('%s, %s, "%s", "%s", "%s"' % (service.name(), display_name, image_path, dll, description))


if __name__ == '__main__':
    main()