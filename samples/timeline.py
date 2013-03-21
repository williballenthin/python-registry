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

    for path in args.registry_hives:
        reg = Registry.Registry(path)

        if args.bodyfile:
            hive = guess_hive_name(path)

            def visitor(timestamp, path):
                try:
                    print u"0|[Registry %s] %s|0|0|0|0|0|%s|0|0|0" % \
                      (hive, path, int(calendar.timegm(timestamp.timetuple())))
                except UnicodeDecodeError:
                    pass

            rec(reg.root(), visitor)
        else:
            items = []
            rec(reg.root(), lambda a, b: items.append((a, b)))
            for i in sorted(items, key=lambda x: x[0]):
                print "%s\t%s" % i

if __name__ == "__main__":
    main()
