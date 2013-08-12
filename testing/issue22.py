#!/usr/bin/python
from Registry import Registry


def main():
    import sys
    hive = sys.argv[1]

    import hashlib
    m = hashlib.md5()
    with open(hive, 'rb') as f:
        m.update(f.read())
    if m.hexdigest() != "26cb15876ceb4fd64476223c2bf1c8e3":
        print "Please use the SYSTEM hive with MD5 26cb15876ceb4fd64476223c2bf1c8e3"
        sys.exit(-1)

    r = Registry.Registry(hive)
    k = r.open("ControlSet001\\Control\\TimeZoneInformation")
    v = k.value("TimeZoneKeyName")
    if v.value() == "Pacific Standard Time":
        print "Passed."
    else:
        print "Failed."
        print "Expected: Pacific Standard Time"
        print "Got: %s (length: %d)" % (v.value(), len(v.value()))
    sys.exit(0)


if __name__ == "__main__":
    main()



