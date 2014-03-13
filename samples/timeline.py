#!/usr/bin/python

from __future__ import print_function
from __future__ import unicode_literals

import os
import calendar

import argparse
from Registry import Registry


def guess_hive_name(path):
    for i in range(len(path)):
        rpath = path[-(i + 1):].lower()
        for guess in ["ntuser", "software", "system",
                      "userdiff", "sam", "default"]:
            if guess in rpath:
                return guess.upper()


def main():
    parser = argparse.ArgumentParser(
        description="Timeline Windows Registry key timestamps")
    parser.add_argument("--bodyfile", action="store_true",
                        help="Output in the Bodyfile 3 format")
    parser.add_argument("registry_hives", type=str, nargs="+",
                        help="Path to the Windows Registry hive to process")
    args = parser.parse_args()

    def rec(key, visitor):
        try:
            visitor(key.timestamp(), key.path())
        except ValueError:
            pass
        for subkey in key.subkeys():
            rec(subkey, visitor)

    for filename in args.registry_hives:
        basename = os.path.basename(filename)
        reg = Registry.Registry(filename)

        if args.bodyfile:
            def visitor(timestamp, path):
                try:
                    print("0|[Registry %s] %s|0|0|0|0|0|%s|0|0|0" % \
                      (basename, path, int(calendar.timegm(timestamp.timetuple()))))
                except UnicodeDecodeError:
                    pass

            rec(reg.root(), visitor)
        else:
            items = []
            rec(reg.root(), lambda a, b: items.append((a, b)))
            for i in sorted(items, key=lambda x: x[0]):
                print("%s\t[Registry %s]%s" % (i[0], basename, i[1]))

if __name__ == "__main__":
    main()
