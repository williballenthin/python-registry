
import re, sys, datetime

from Registry import Registry


SB_MRU_TYPE_PREDEFINED = 0x1F
SB_MRU_TYPE_ARCHIVE = 0x32
SB_MRU_TYPE_NAMEEARLY = 0x2E
SB_MRU_TYPE_NAMEVERYEARLY = 0x2F

def dosdate(dosdate, dostime):
    try:
        t  = ord(dosdate[1]) << 8
        t |= ord(dosdate[0])
        day   = t & 0b0000000000011111
        month = (t & 0b0000000111100000) >> 5
        year  = (t & 0b1111111000000000) >> 9
        year += 1980
        
        t = ord(dostime[0]) << 8
        t |= ord(dostime[1])
        sec     = t & 0b0000000000011111
        sec *= 2
        minute  = (t & 0b0000011111100000) >> 5
        hour    = (t & 0b1111100000000000) >> 11

        return datetime.datetime(year, month, day, hour, minute, sec)
    except:
        return datetime.datetime.min

def get_shellbags(registry):
    keys = {}
    shellbags = []
    windows = registry.open("Software\\Microsoft\\Windows\\ShellNoRoam")
    bagmru = windows.subkey("BagMRU")
    bags = windows.subkey("Bags")

    def shellbag_rec(key, bag_prefix, path_prefix):
        for value in key.values():
            if not re.match("\d+", value.name()):
                continue
            mru_type = ord(value.value()[2])

            # get ASCII name at known offset
            if mru_type == SB_MRU_TYPE_NAMEEARLY:
                nameAStart = 0xA
            elif mru_type == SB_MRU_TYPE_NAMEVERYEARLY:
                nameAStart = 0x3
            else:
                nameAStart = 0xE
            nameA = value.value()[nameAStart:].partition(b"\x00")[0].decode("ascii", "ignore")

            # next, get the full unicode version
            if mru_type == SB_MRU_TYPE_PREDEFINED:
                nameW = "??"
                mtime = datetime.datetime.min
                atime = datetime.datetime.min
                ctime = datetime.datetime.min
            elif mru_type == SB_MRU_TYPE_NAMEEARLY:
                nameW = value.value()[0xA:].partition(b"\x00\x00")[0]
                mtime = datetime.datetime.min
                atime = datetime.datetime.min
                ctime = datetime.datetime.min
            elif mru_type == SB_MRU_TYPE_NAMEVERYEARLY:
                nameW = nameA.encode("utf16", "ignore")[2:] # ignore leading 2 bytes (byte ordering)
                mtime = datetime.datetime.min
                atime = datetime.datetime.min
                ctime = datetime.datetime.min
            else:
#                needle = nameA.lower().partition("~")[0].encode("utf16")[2:]
#                wide_start = value.value().lower().find(needle)
                anchor = value.value().lower().find(b"\x03\x00\x04\x00\xEF\xBE")
                wide_start = anchor + 18
                nameW = value.value()[wide_start:].decode("utf16", "replace").partition(b"\x00")[0]

                ddate = value.value()[8:10]
                dtime = value.value()[10:12]
                mtime = dosdate(ddate, dtime)

                ddate = value.value()[anchor + 6:anchor + 8]
                dtime = value.value()[anchor + 8:anchor + 10]
                ctime = dosdate(ddate, dtime)

                ddate = value.value()[anchor + 10:anchor + 12]
                dtime = value.value()[anchor + 12:anchor + 14]
                atime = dosdate(ddate, dtime)
            try:
                path = path_prefix + "\\" + nameW
                shellbags.append({
                        "path": path,
                        "mtime": mtime,
                        "atime": atime,
                        "ctime": ctime
                        })

                print hex(mru_type) + " " + bag_prefix + "\\" + value.name() + "  " + path

                if mru_type == SB_MRU_TYPE_ARCHIVE:
                    # dont recurse, because children are messed up
                    continue

                shellbag_rec(key.subkey(value.name()), bag_prefix + "\\" + value.name(), path_prefix + "\\" + nameW)
            except UnicodeDecodeError:
                continue

    shellbag_rec(bagmru, "", "")
    print "MTIME, ATIME, CTIME, PATH"
    for shellbag in shellbags:
        print "%s, %s, %s, %s" % (shellbag["mtime"], shellbag["atime"], shellbag["ctime"], shellbag["path"])



def usage():
    return "  USAGE:\n\t%s <Windows Registry file>" % sys.argv[1]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])

    get_shellbags(registry)



