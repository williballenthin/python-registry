#!/usr/bin/python

#    This file is part of python-registry.
#
#   Copyright 2011 Will Ballenthin <willi.ballenthin@mandiant.com>
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

import re, sys, datetime
from Registry import Registry


SB_MRU_TYPE_PREDEFINED = 0x1F
SB_MRU_TYPE_ARCHIVE = 0x32
SB_MRU_TYPE_UNICODEONLY = 0x2E
SB_MRU_TYPE_NAMEIMMEDIATE = 0x2F
SB_MRU_TYPE_NORMAL = 0x31

def dosdate(dosdate, dostime):
    """
    `dosdate`: 2 bytes, little endian.
    `dostime`: 2 bytes, little endian.
    returns: datetime.datetime or datetime.datetime.min on error
    """
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
    # TODO try both Shell and ShellNoRoam
    try:
        # Windows XP NTUSER.DAT location
        windows = registry.open("Software\\Microsoft\\Windows\\ShellNoRoam")
    except Registry.RegistryKeyNotFoundException:
        try:
            # Windows 7 UsrClass.dat location
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
            elif mru_type == SB_MRU_TYPE_NORMAL:
                nameAStart = 0xE
            else:
                nameAStart = 0x00
            nameA = value.value()[nameAStart:].partition(b"\x00")[0].decode("ascii", "ignore")

            # next, get the full unicode version
            if mru_type == SB_MRU_TYPE_PREDEFINED:
                # At this point, the predefined keys are unknown. 
                # A general survey will have to be made in order to identify
                # the meaning of the predefined keys
                nameW = "??%s" % (value.name()) 
            elif mru_type == SB_MRU_TYPE_UNICODEONLY:
                # the finds the end of the utf16 string in the binary
                # we know it must end in 00 00, but it could end in 00 00 00
                # if the last character is ASCII. We dont want to truncate 
                # the last character in that case
                bin = value.value()[0xA:]
                end_idx = bin.find(b"\x00\x00")
                if end_idx % 2 == 1:
                    end_idx += 1
                nameW = bin[:end_idx]
                try:
                    nameW = nameW.decode("utf16")
                except UnicodeDecodeError:
                    # This is something to research further, but many 0x2E bags are invalid
                    # and we can detect this during decoding. 
                    # This is not perfect, though, and some bad entries slip through.
                    continue
            elif mru_type == SB_MRU_TYPE_NAMEIMMEDIATE:
                nameW = nameA
            elif mru_type == SB_MRU_TYPE_NORMAL or mru_type == SB_MRU_TYPE_ARCHIVE:
                # Windows XP SP3 seems to always have this byte sequence at a predictable offset
                # We could try to use the nameA to find nameW, however it gets really messy
                # with spaces and upper/lowercasing
                anchor = value.value().lower().find(b"\x03\x00\x04\x00\xEF\xBE")

                # In the standard bag, the UTF16 representation ends 7 bytes from the 
                # end of the key.
                nameWstart = value.value().rfind(b"\x00\x00", 0, -7)
                nameW = value.value()[nameWstart + 2:].decode("utf16", "replace").partition(b"\x00")[0]

                ddate = value.value()[8:10]
                dtime = value.value()[10:12]
                mtime = dosdate(ddate, dtime)

                # TODO don't key off the anchor
                ddate = value.value()[anchor + 6:anchor + 8]
                dtime = value.value()[anchor + 8:anchor + 10]
                ctime = dosdate(ddate, dtime)

                ddate = value.value()[anchor + 10:anchor + 12]
                dtime = value.value()[anchor + 12:anchor + 14]
                atime = dosdate(ddate, dtime)

            else:
                nameW = "??%s" % (value.name()) 

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

            shellbag_rec(key.subkey(value.name()), bag_prefix + "\\" + value.name(), path)

    shellbag_rec(bagmru, "", "")
    print "MTIME, ATIME, CTIME, PATH"
    for shellbag in shellbags:
        try:
            print "%s, %s, %s, %s" % (shellbag["mtime"], shellbag["atime"], shellbag["ctime"], shellbag["path"])
        except UnicodeEncodeError:
            print list(shellbag["path"])
            sys.exit(-1)

def usage():
    return "  USAGE:\n\t%s <Windows Registry file>" % sys.argv[1]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])

    get_shellbags(registry)



