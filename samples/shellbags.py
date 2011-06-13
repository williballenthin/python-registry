
import re, sys, datetime

from Registry import Registry


SB_MRU_TYPE_PREDEFINED = 0x1F
SB_MRU_TYPE_ARCHIVE = 0x32
SB_MRU_TYPE_UNICODEONLY = 0x2E
SB_MRU_TYPE_NAMEIMMEDIATE = 0x2F

def dosdate(dosdate, dostime):
    try:
        t  = ord(dosdate[1]) << 8
        t |= ord(dosdate[0])
        day   = t & 0b0000000000011111
        month = (t & 0b0000000111100000) >> 5
        year  = (t & 0b1111111000000000) >> 9
        year += 1980
        
        t = ord(dostime[1]) << 8
        t |= ord(dostime[0])
        sec     = t & 0b0000000000011111
        sec *= 2
        minute  = (t & 0b0000011111100000) >> 5
        hour    = (t & 0b1111100000000000) >> 11

        return datetime.datetime(year, month, day, hour, minute, sec)
    except:
        return datetime.datetime.min

def get_shellbags(registry):
    shellbags = []
    try:
        windows = registry.open("Software\\Microsoft\\Windows\\ShellNoRoam")
    except Registry.RegistryKeyNotFoundException:
        try:
            windows = registry.open("Local Settings\\Software\\Microsoft\\Windows\\Shell")
        except Registry.RegistryKeyNotFoundException:
            print "Unable to find shellbag key."
            sys.exit(-1)
    bagmru = windows.subkey("BagMRU")

    def shellbag_rec(key, bag_prefix, path_prefix):
        """
        `key`: The current 'BagsMRU' key to recurse into.
        `bag_prefix`: A string containing the current subkey path of the relevant 'Bags' key.
            It will look something like '1\\2\\3\\4'.
        `path_prefix` A string containing the current human-readable, file system path so far constructed.
        """
        for value in key.values():
            if not re.match("\d+", value.name()):
                continue
            mru_type = ord(value.value()[2])

            # default timestamps
            mtime = datetime.datetime.min
            atime = datetime.datetime.min
            ctime = datetime.datetime.min

            # get ASCII name at known offset
            if mru_type == SB_MRU_TYPE_UNICODEONLY:
                nameAStart = 0xA
            elif mru_type == SB_MRU_TYPE_NAMEIMMEDIATE:
                nameAStart = 0x3
            else:
                nameAStart = 0xE
            nameA = value.value()[nameAStart:].partition(b"\x00")[0].decode("ascii", "ignore")

            # next, get the full unicode version
            if mru_type == SB_MRU_TYPE_PREDEFINED:
#                nameW = "??"
                nameW = "[" + bag_prefix + "|" + value.name() + "]"
            elif mru_type == SB_MRU_TYPE_UNICODEONLY:
                # the finds the end of the utf16 string in the binary
                # we know it must end in 00 00, but it could end in 00 00 00
                # if the last character is ASCII. We dont want to truncate 
                # the last character in that case
                bin = value.value()[0xA:]
                end_idx = bin.find(b"\x00\x00")
                if end_idx % 2 == 1:
                    end_idx += 1
                nameW = bin[:end_idx].decode("utf16")
            elif mru_type == SB_MRU_TYPE_NAMEIMMEDIATE:
                nameW = nameA
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

                if mru_type == SB_MRU_TYPE_ARCHIVE:
                    # dont recurse, because children are messed up
                    continue

                shellbag_rec(key.subkey(value.name()), bag_prefix + "\\" + value.name(), path_prefix + "\\" + nameW)
            except UnicodeDecodeError:
                continue

    shellbag_rec(bagmru, "", "")
#    print "MTIME, ATIME, CTIME, PATH"
    for shellbag in shellbags:
#        print "%s, %s, %s, %s" % (shellbag["mtime"], shellbag["atime"], shellbag["ctime"], shellbag["path"])
        try:
            print "%s" % (shellbag["path"])
        except UnicodeEncodeError:
            print list(shellbag["path"])



def usage():
    return "  USAGE:\n\t%s <Windows Registry file>" % sys.argv[1]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])

    get_shellbags(registry)



