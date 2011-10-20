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

import re, sys, datetime, time
import struct, array
from Registry import Registry

# Global
verbose = True

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

def align(offset, alignment):
    """
    Return the offset aligned to the nearest greater given alignment
    Arguments:
    - `offset`: An integer
    - `alignment`: An integer
    """
    if offset % alignment == 0:
        return offset
    return offset + (alignment - (offset % alignment))

def debug(message):
    global verbose
    
    if verbose:
        print "# [d] %s" % (message)

def warning(message):
    print "# [w] %s" % (message)

class SHITEMTYPE:
    '''
    This is like an enum...
    These are the 'supported' SHITEM types
    '''
    UNKNOWN0 = 0x00
    UNKNOWN1 = 0x01
    UNKNOWN2 = 0x2E
    FILE_ENTRY0 = 0x31
    FILE_ENTRY1 = 0x32
    FILE_ENTRY2 = 0xB1
    FOLDER_IDENTIFIER = 0x1F
    VOLUME_NAME = 0x2F
    NETWORK_VOLUME_NAME0 = 0x41
    NETWORK_VOLUME_NAME1 = 0x42
    NETWORK_VOLUME_NAME2 = 0x46
    NETWORK_VOLUME_NAME3 = 0x47
    NETWORK_SHARE = 0xC3
    URI = 0x61
    CONTROL_PANEL = 0x71

class ShellbagException(Exception):
    """
    Base Exception class for shellbag parsing.
    """    
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(ShellbagException, self).__init__()
        self._value = value

    def __str__(self):
        return "Shellbag Exception: %s" % (self._value)

    def __unicode__(self):
        return u"Shellbag Exception: %s" % (self._value)

class ParseException(ShellbagException):
    """
    An exception to be thrown during parsing, such as 
    when an invalid header is encountered.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(ParseException, self).__init__(value)

    def __str__(self):
        return "Parse Exception(%s)" % (self._value)

    def __unicode__(self):
        return u"Parse Exception(%s)" % (self._value)

class OverrunBufferException(ParseException):
    def __init__(self, readOffs, bufLen):
        tvalue = "read: %s, buffer length: %s" % (hex(readOffs), hex(bufLen))
        super(ParseException, self).__init__(tvalue)

    def __str__(self):
        return "Tried to parse beyond the end of the file (%s)" % (self._value)

    def __unicode__(self):
        return u"Tried to parse beyond the end of the file (%s)" % (self._value)

class Block(object):
    """ 
    Base class for structured blocks used in parsing.
    A block is associated with a offset into a byte-string.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing binary data.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        self._buf = buf
        self._offset = offset
        self._parent = parent

    def unpack_byte(self, offset):
        """
        Returns a little-endian unsigned byte from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<B", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_word(self, offset):
        """
        Returns a little-endian WORD (2 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<H", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def pack_word(self, offset, word):
        """
        Applies the little-endian WORD (2 bytes) to the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `word`: The data to apply.
        """
        o = self._offset + offset
        return struct.pack_into("<H", self._buf, o, word)

    def unpack_dword(self, offset):
        """
        Returns a little-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<I", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_int(self, offset):
        """
        Returns a little-endian signed integer (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<i", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_qword(self, offset):
        """
        Returns a little-endian QWORD (8 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset
        try:
            return struct.unpack_from("<Q", self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_string(self, offset, length=False):
        """
        Returns a string from the relative offset with the given length.
        The string does not include the final NULL character.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: (Optional) The length of the string. If no length is provided,
                       the string runs until a NULL.
        Throws:
        - `OverrunBufferException`
        - `IndexError`
        """
        o = self._offset + offset

        if not length:
            end = self._buf.find("\x00", o)
            length = end - o

        try:
            return struct.unpack_from("<%ds" % (length), self._buf, o)[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_wstring(self, offset, length=False):
        """
        Returns a UTF-16 decoded string from the relative offset with the given length,
        where each character is a wchar (2 bytes). The string does not include the final
        NULL character.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: (Optional) The length of the string. If no length is provided,
                       the string runs until a double NULL.
        Throws:
        - `UnicodeDecodeError`
        - `IndexError`
        """
        if not length:
            o = self._offset + offset
            end = self._buf.find("\x00\x00", o)

            if self._buf[end - 2] == "\x00":
                # then the last UTF-16 character was in the ASCII range
                # and the \x00\x00 matched on the second half of the char
                # and continued into the final null char
                #
                # eg.     \x00 A \x00 B \x00 \x00 \x00
                #        ----+ +----+ +----+ +-------+      
                end += 1
            else:
                # the \x00\x00 matched on the final null
                #
                # eg.     A \x00 \xFF \xFF \x00 \x00
                #         +----+ +-------+ +-------+ 
                pass
            length = end - o
        
        return self._buf[self._offset + offset:self._offset + offset + 2 * length].decode("utf16")

    def unpack_dosdate(self, offset):
        """
        Returns a datetime from the DOSDATE and DOSTIME starting at the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        try:
            o = self._offset + offset
            return dosdate(self._buf[o:o + 2], self._buf[o + 2:o + 4])
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def absolute_offset(self, offset):
        """
        Get the absolute offset from an offset relative to this block
        Arguments:
        - `offset`: The relative offset into this block.
        """
        return self._offset + offset

    def parent(self):
        """
        Get the parent block. See the class documentation for what the parent link is.
        """
        return self._parent

    def offset(self):
        """
        Equivalent to self.absolute_offset(0x0), which is the starting offset of this block.
        """
        return self._offset

class SHITEM(Block):
    def __init__(self, buf, offset, parent):
        debug("SHITEM @ %s." % (hex(offset)))
        super(SHITEM, self).__init__(buf, offset, parent)

        self._off_size = 0x0    # UINT16
        self._off_type = 0x2    # UINT8

    def __unicode__(self):
        return u"SHITEM @ %s." % (hex(self.offset()))

    def __str__(self):
        return "SHITEM @ %s." % (hex(self.offset()))

    def size(self):
        return self.unpack_word(self._off_size)

    def type(self):
        return self.unpack_word(self._off_type)

    def name(self):
        return "??"

    def m_date(self):
        return datetime.datetime.min()

    def a_date(self):
        return datetime.datetime.min()

    def cr_date(self):
        return datetime.datetime.min()

class SHITEM_FILEENTRY(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_FILEENTRY @ %s." % (hex(offset)))
        super(SHITEM_FILEENTRY, self).__init__(buf, offset, parent)
        
        self._off_flags = 0x3      # UINT8
        self._off_filesize = 0x4   # UINT32
        self._off_date = 0x8       # DOSDATE
        self._off_fileattrs = 0xC  # UINT16
        self._off_short_name = 0xE # ASCII string

        offset = self._off_short_name + len(self.short_name()) + 1
        offset = align(offset, 2)

        self._off_ext_size = offset
        offset += 2

        self._off_ext_version = offset
        offset += 2

        if self.ext_version() >= 0x0003:
            offset += 4 # unknown

            self._off_cr_date = offset 
            offset += 4

            self._off_a_date = offset 
            offset += 4

            offset += 2 # unknown
        else:
            self._off_cr_date = False
            self._off_a_date = False

        if self.ext_version() >= 0x0007:
            offset += 8 # fileref
            offset += 8 # unknown
            
            self._off_long_name_size = offset
            offset += 2

            if self.ext_version() >= 0x0008:
                offset += 4 # unknown

            self._off_long_name = offset
            offset += self.long_name_size()
        elif self.ext_version() >= 0x0003:
            self._off_long_name_size = False
            self._off_long_name = offset
        else:
            self._off_long_name_size = False
            self._off_long_name = False

    def __unicode__(self):
        return u"SHITEM_FILEENTRY @ %s: %s." % (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_FILEENTRY @ %s: %s." % (hex(self.offset()), self.name())

    def filesize(self):
        return self.unpack_dword(self._off_filesize)

    def m_date(self):
        return self.unpack_dosdate(self._off_date)

    def short_name(self):
        return self.unpack_string(self._off_short_name)

    def ext_version(self):
        return self.unpack_word(self._off_ext_version)
        
    def cr_date(self):
        if self._off_cr_date:
            return self.unpack_dosdate(self._off_cr_date)
        else:
            return datetime.datetime.min

    def a_date(self):
        if self._off_a_date:
            return self.unpack_dosdate(self._off_a_date)
        else:
            return datetime.datetime.min

    def long_name_size(self):
        if self._off_long_name_size:
            return self._off_long_name_size
        elif self._off_long_name:
            return len(self.long_name()) + 2 # include final NULL
        else:
            return 0

    def long_name(self):
        if self._off_long_name and self._off_long_name_size:
            return self.unpack_wstring(self._off_long_name, self.long_name_size())
        elif self._off_long_name:
            return self.unpack_wstring(self._off_long_name)
        else:
            return ""

    def name(self):
        n = self.long_name()
        if len(n) > 0:
            return n
        return self.short_name()

class SHITEMLIST(Block):
    def __init__(self, buf, offset, parent):
        debug("SHITEMLIST @ %s." % (hex(offset)))
        super(SHITEMLIST, self).__init__(buf, offset, parent)

    def items(self):
        off = self.offset()

        while True:
            size = self.unpack_word(off)
            if size == 0:
                return

            type = self.unpack_word(off + 2)
            if type == SHITEMTYPE.FILE_ENTRY0 or \
               type == SHITEMTYPE.FILE_ENTRY1 or \
               type == SHITEMTYPE.FILE_ENTRY2:
                item = SHITEM_FILEENTRY(self._buf, off, self)
            else:
                item = SHITEM(self._buf, off, self)

            yield item
            off += item.size()

    def __unicode__(self):
        return u"SHITEMLIST @ %s." % (hex(self.offset()))

    def __str__(self):
        return "SHITEMLIST @ %s." % (hex(self.offset()))

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

            print bag_prefix + "\\" + value.name()

            mtime = datetime.datetime.min
            atime = datetime.datetime.min
            ctime = datetime.datetime.min
            nameW = "??"

            l = SHITEMLIST(value.value(), 0, False)
            for i in l.items():
                # assume only one item here, and take the last
                try:
                    nameW = i.name()
                    mtime = i.m_date()
                    ctime = i.cr_date()
                    atime = i.a_date()
                except:
                    pass

            path = path_prefix + "\\" + nameW
            shellbags.append({
                    "path": path,
                    "mtime": mtime,
                    "atime": atime,
                    "ctime": ctime
                    })

            shellbag_rec(key.subkey(value.name()), bag_prefix + "\\" + value.name(), path)

    shellbag_rec(bagmru, "", "")
    for shellbag in shellbags:
        try:
            print shellbag_bodyfile(shellbag["mtime"], shellbag["atime"], shellbag["ctime"], shellbag["path"])
        except UnicodeEncodeError:
            print "#" + str(list(shellbag["path"]))
            pass

def shellbag_bodyfile(m, a, c, path):
    try:
        modified = int(time.mktime(m.timetuple()))    
    except ValueError:
        modified = int(time.mktime(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))

    try:
        accessed = int(time.mktime(a.timetuple()))
    except ValueError:
        accessed = int(time.mktime(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))

    try:
        created  = int(time.mktime(c.timetuple()))
    except ValueError:
        created = int(time.mktime(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))

    changed = int(time.mktime(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))

    return u"0|Shellbag %s|0|0|0|0|0|%s|%s|%s|%s" % (path, modified, accessed, changed, created)


def usage():
    return "  USAGE:\n\t%s <Windows Registry file>" % sys.argv[1]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])

    get_shellbags(registry)
