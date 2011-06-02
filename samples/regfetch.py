import sys
from Registry import Registry

def usage():
    return "  USAGE:\n\t%s <Windows Registry file> <Registry key path> <Registry Value>" % sys.argv[1]

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])
    key = registry.open(sys.argv[2])
    value = key.value(sys.argv[3])

    sys.stdout.write(value.value())
