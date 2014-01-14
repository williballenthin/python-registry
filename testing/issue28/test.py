import sys
import hashlib

from Registry import Registry

def rec(key):
    try:
        _ = key.name()
        _ = key.timestamp()
    except UnicodeDecodeError as e:
        print("Exception(key): %s" % (repr(e)))
        print(key.path())
        raise

    for v in key.values():
        try:
            _ = v.value_type_str()
            _ = v.value()
            _ = v.name()
        except UnicodeDecodeError as e:
            print("Exception(value): %s" % (repr(e)))
            print("%s : %s" % (key.path(), v.name()))
            raise

    for k in key.subkeys():
        rec(k)

def main():
    filename = sys.argv[1]
    m = hashlib.md5()
    with open(filename, "rb") as f:
        m.update(f.read())
    if m.hexdigest() != "2cd094fbce4db25eba32edf306c0fd62":
        print("Please use the SYSTEM hive with MD5 2cd094fbce4db25eba32edf306c0fd62")
        sys.exit(-1)

    r = Registry.Registry(filename)
    rec(r.root())
    print("Test passed.")

if __name__ == "__main__":
    main()
