#!/usr/bin/python
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
    parser.add_argument("registry_hive", type=str,
                        help="Path to the Windows Registry hive to process")
    args = parser.parse_args()
    items = []

    def rec(key):
        try:
            items.append((key.timestamp(), key.path()))
        except ValueError:
            pass
        for subkey in key.subkeys():
            rec(subkey)

    for path in args.registry_hive:
        reg = Registry.Registry(args.registry_hive)
        rec(reg.root())

    if args.bodyfile:
        hive = guess_hive_name(args.registry_hive)
        for timestamp, path in items:
            print u"0|[Registry %s] %s|0|0|0|0|0|%s|0|0|0" % \
                (hive, path, int(calendar.timegm(timestamp.timetuple())))

    else:
        for i in sorted(items, key=lambda x: x[0]):
            print "%s\t%s" % i

if __name__ == "__main__":
    main()
