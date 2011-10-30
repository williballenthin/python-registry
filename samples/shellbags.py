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
verbose = False

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
        
        t  = ord(dostime[1]) << 8
        t |= ord(dostime[0])
        sec     = t & 0b0000000000011111
        sec    *= 2
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

def error(message):
    print "# [e] %s" % (message)
    sys.exit(-1)

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
    FOLDER_ENTRY = 0x1F
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
    """
    An exception to be thrown during parsing when something is unpack into 
    or from a location beyond the boundaries of a buffer.
    """
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
        self._fields = []

    def _prepare_fields(self, fields=False):
        """
        Declaratively add fields to this block.
        self._fields should contain a list of tuples ("type", "name", offset).
        This method will dynamically add corresponding offset and unpacker methods
          to this block.
        Arguments:
        - `fields`: (Optional) A list of tuples to add. Otherwise, 
            self._fields is used.
        """
        for field in fields or self._fields:
            def handler():
                f = getattr(self, "unpack_" + field[0])
                return f(*(field[2:]))
            setattr(self, field[1], handler)
            debug("(%s) %s @ %s : %s" % (field[0].upper(), 
                                         field[1], 
                                         hex(self.absolute_offset(field[2])),
                                         str(handler())))
            setattr(self, "_off_" + field[1], field[2])

    def _f(self, type, name, offset, length=False):
        """
        A shortcut to add a field.
        Arguments:
        - `t`: A tuple to add.
        """
        if length:
            self._prepare_fields([(type, name, offset, length)])
        else:
            self._prepare_fields([(type, name, offset)])

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
            return struct.unpack_from("<%ds" % (length), self._buf, o)[0].partition("\x00")[0]
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_wstring(self, offset, ilength=False):
        """
        Returns a UTF-16 decoded string from the relative offset with 
        the given length, where each character is a wchar (2 bytes). 
        The string does not include the final
        NULL character.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: (Optional) The length of the string. If no length is provided,
                       the string runs until a double NULL.
        Throws:
        - `UnicodeDecodeError`
        - `IndexError`
        """
        if not ilength:
            o = self._offset + offset
            end = self._buf.find("\x00\x00", o)
            if end - 2 <= o:
                return ""

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
        else:
            length = ilength
        return self._buf[self._offset + offset:self._offset + offset + length].decode("utf16").partition("\x00")[0]

    def unpack_dosdate(self, offset):
        """
        Returns a datetime from the DOSDATE and DOSTIME starting at 
        the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        try:
            o = self._offset + offset
            return dosdate(self._buf[o:o + 2], self._buf[o + 2:o + 4])
        except struct.error:
            raise OverrunBufferException(o, len(self._buf))

    def unpack_guid(self, offset):
        """
        Returns a string containing a GUID starting at the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        Throws:
        - `OverrunBufferException`
        """
        o = self._offset + offset

        try:
            bin = self._buf[o:o + 16]
        except IndexError:
            raise OverrunBufferException(o, len(self._buf))

        # Yeah, this is ugly
        h = map(ord, bin)
        return "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" % \
            (h[3], h[2], h[1], h[0],
             h[5], h[4],
             h[7], h[6],
             h[8], h[9],
             h[10], h[11], h[12], h[13], h[14], h[15])

    def absolute_offset(self, offset):
        """
        Get the absolute offset from an offset relative to this block
        Arguments:
        - `offset`: The relative offset into this block.
        """
        return self._offset + offset

    def parent(self):
        """
        Get the parent block. See the class documentation for what the 
        parent link is.
        """
        return self._parent

    def offset(self):
        """
        Equivalent to self.absolute_offset(0x0), which is the starting 
        offset of this block.
        """
        return self._offset

class SHITEM(Block):
    def __init__(self, buf, offset, parent):
        super(SHITEM, self).__init__(buf, offset, parent)

        self._f("word", "size", 0x0)
        self._f("byte", "type", 0x2)
        debug("SHITEM @ %s of type %s." % (hex(offset), hex(self.type())))

    def __unicode__(self):
        return u"SHITEM @ %s." % (hex(self.offset()))

    def __str__(self):
        return "SHITEM @ %s." % (hex(self.offset()))

    def name(self):
        return "??"

    def m_date(self):
        return datetime.datetime.min

    def a_date(self):
        return datetime.datetime.min

    def cr_date(self):
        return datetime.datetime.min

known_guids = {
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "CSIDL_SYSTEM",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places",
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "{Unknown CSIDL}",
    "22877a6d-37a1-461a-91b0-dbda5aaebc99": "{Unknown CSIDL}",
    "2400183a-6185-49fb-a2d8-4a392a602ba3": "Public Videos",
    "2559a1f1-21d7-11d4-bdaf-00c04f60b9f0": "{Unknown CSIDL}",
    "2559a1f3-21d7-11d4-bdaf-00c04f60b9f0": "{Unknown CSIDL}",
    "26ee0668-a00a-44d7-9371-beb064c98683": "{Unknown CSIDL}",
    "3080f90e-d7ad-11d9-bd98-0000947b0257": "{Unknown CSIDL}",
    "3214fab5-9757-4298-bb61-92a9deaa44ff": "Public Music",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "4336a54d-038b-4685-ab02-99bb52d3fb8b": "{Unknown CSIDL}",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "5399e694-6ce5-4d6c-8fce-1d8870fdcba0": "Control Panel",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "724ef170-a42d-4fef-9f26-b60e846fba4f": "Administrative Tools",
    "7b0db17d-9cd2-4a93-9733-46cc89022e7c": "Documents Library",
    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "Program Files (x86)",
    "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer (Homepage)",
    "905e63b6-c1bf-494e-b29c-65b732d3d21a": "Program Files",
    "9e52ab10-f80d-49df-acb8-4330f5687855": "Temporary Burn Folder",
    "a305ce99-f527-492b-8b1a-7e76fa98d6e4": "Installed Updates",
    "b6ebfb86-6907-413c-9af7-4fc2abf07cc5": "Public Pictures",
    "c1bae2d0-10df-4334-bedd-7aa20b227a9d": "Common OEM Links",
    "cce6191f-13b2-44fa-8d14-324728beef2c": "{Unknown CSIDL}",
    "d0384e7d-bac3-4797-8f14-cba229b392b5": "Common Administrative Tools",
    "d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27": "System32 (x86)",
    "de61d971-5ebc-4f02-a3a9-6c82895e5c04": "Get Programs",
    "df7266ac-9274-4867-8d55-3bd661de872d": "Programs and Features",
    "dfdf76a2-c82a-4d63-906a-5644ac457385": "Public",
    "de974d24-d9c6-4d3e-bf91-f4455120b917": "Common Files",
    "ed228fdf-9ea8-4870-83b1-96b02cfe0d52": "My Games",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network", 
    "f38bf404-1d43-42f2-9305-67de0b28fc23": "Windows",
    "f3ce0f7c-4901-4acc-8648-d5d44b04ef8f": "Users Files",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
}

class SHITEM_FOLDERENTRY(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_FOLDERENTRY @ %s." % (hex(offset)))
        super(SHITEM_FOLDERENTRY, self).__init__(buf, offset, parent)
        
        self._off_folderid = 0x3      # UINT8
        self._f("guid", "guid", 0x4)

    def __unicode__(self):
        return u"SHITEM_FOLDERENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_FOLDERENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def folder_id(self):
        id = self.unpack_byte(self._off_folderid)
        
        if id == 0x00:
            return "INTERNET_EXPLORER"
        elif id == 0x42:
            return "LIBRARIES"
        elif id == 0x44:
            return "USERS"
        elif id == 0x48:
            return "MY_DOCUMENTS"
        elif id == 0x50:
            return "MY_COMPUTER"
        elif id == 0x58:
            return "NETWORK"
        elif id == 0x60:
            return "RECYCLE_BIN"
        elif id == 0x68:
            return "INTERNET_EXPLORER"
        elif id == 0x70:
            return "UKNOWN"
        elif id == 0x80:
            return "MY_GAMES"
        else:
            return ""

    def name(self):
        if self.guid() in known_guids:
            return known_guids[self.guid()]
        else:
            return "{%s: %s}" % (self.folder_id(), self.guid())

class SHITEM_UNKNOWNENTRY0(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_UNKNOWNENTRY0 @ %s." % (hex(offset)))
        super(SHITEM_UNKNOWNENTRY0, self).__init__(buf, offset, parent)
        
        # pretty much completely unknown
        # TODO, if you have time for research

    def __unicode__(self):
        return u"SHITEM_UNKNOWNENTRY0 @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_UNKNOWNENTRY0 @ %s: %s." % \
          (hex(self.offset()), self.name())

    def name(self):
        return "??"

class SHITEM_UNKNOWNENTRY2(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_UNKNOWNENTRY2 @ %s." % (hex(offset)))
        super(SHITEM_UNKNOWNENTRY2, self).__init__(buf, offset, parent)

        self._f("byte", "flags", 0x3)
        self._f("guid", "guid", 0x4)

    def __unicode__(self):
        return u"SHITEM_UNKNOWNENTRY2 @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_UNKNOWNENTRY2 @ %s: %s." % \
          (hex(self.offset()), self.name())

    def name(self):
        if self.guid() in known_guids:
            return known_guids[self.guid()]
        else:
            return "{%s}" % (self.guid())

class SHITEM_URIENTRY(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_URIENTRY @ %s." % (hex(offset)))
        super(SHITEM_URIENTRY, self).__init__(buf, offset, parent)

        self._f("dword", "flags", 0x3)
        self._f("wstring", "uri", 0x7)

    def __unicode__(self):
        return u"SHITEM_URIENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_URIENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def name(self):
        return self.uri()

class SHITEM_CONTROLPANELENTRY(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_CONTROLPANELENTRY @ %s." % (hex(offset)))
        super(SHITEM_CONTROLPANELENTRY, self).__init__(buf, offset, parent)

        self._f("byte", "flags", 0x3)
        self._f("guid", "guid", 0xD)

    def __unicode__(self):
        return u"SHITEM_CONTROLPANELENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_CONTROLPANELENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def name(self):
        if self.guid() in known_guids:
            return known_guids[self.guid()]
        else:
            return "{%s}" % (self.guid())

class SHITEM_VOLUMEENTRY(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_VOLUMEENTRY @ %s." % (hex(offset)))
        super(SHITEM_VOLUMEENTRY, self).__init__(buf, offset, parent)

        self._f("string", "name", 0x3)

    def __unicode__(self):
        return u"SHITEM_VOLUMEENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_VOLUMEENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

class SHITEM_NETWORKVOLUMEENTRY(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_NETWORKVOLUMEENTRY @ %s." % (hex(offset)))
        super(SHITEM_NETWORKVOLUMEENTRY, self).__init__(buf, offset, parent)

        self._f("byte", "flags", 0x4)
        self._off_name = 0x5

    def __unicode__(self):
        return u"SHITEM_NETWORKVOLUMEENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_NETWORKVOLUMEENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def name(self):
        if self.flags() & 0x2:
            return self.unpack_string(self._off_name)
        return ""

    def description(self):
        if self.flags() & 0x2:
            return self.unpack_string(self._off_name + len(self.name()) + 1)
        return ""

class SHITEM_NETWORKSHAREENTRY(SHITEM):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_NETWORKSHAREENTRY @ %s." % (hex(offset)))
        super(SHITEM_NETWORKSHAREENTRY, self).__init__(buf, offset, parent)

        self._f("byte", "flags", 0x4)
        self._f("string", "path", 0x5)
        self._f("string", "description", 0x5 + len(self.path()) + 1)

    def __unicode__(self):
        return u"SHITEM_NETWORKSHAREENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_NETWORKSHAREENTRY @ %s: %s." % \
          (hex(self.offset()), self.name())

    def name(self):
        return self.path()

class Fileentry(SHITEM):
    """
    The Fileentry structure is used both in the BagMRU and Bags keys with
    minor differences (eg. sizeof and location of size field).
    """
    def __init__(self, buf, offset, parent, filesize_offset):
        debug("Fileentry @ %s." % (hex(offset)))
        super(Fileentry, self).__init__(buf, offset, parent)

        off = filesize_offset
        self._f("dword", "filesize", off); off += 4
        self._f("dosdate", "m_date", off); off += 4
        self._f("word", "fileattrs", off); off += 2
        self._f("string", "short_name", off)

        off += len(self.short_name()) + 1
        off = align(off, 2)

        self._f("word", "ext_size", off); off += 2
        self._f("word", "ext_version", off); off += 2

        if self.ext_version() >= 0x03:
            off += 4 # unknown

            self._f("dosdate", "cr_date", off); off += 4
            self._f("dosdate", "a_date", off); off += 4

            off += 4 # unknown
        else:
            self.cr_date = lambda x: datetime.datetime.min
            self.a_date = lambda x: datetime.datetime.min

        if self.ext_version() >= 0x0007:
            off += 8 # fileref
            off += 8 # unknown

            self._off_long_name_size = off
            off += 2

            if self.ext_version() >= 0x0008:
                off += 4 # unknown

            self._off_long_name = off
            off += self.long_name_size()
        elif self.ext_version() >= 0x0003:
            self._off_long_name_size = False
            self._off_long_name = off
            debug("(WSTRING) long_name @ %s" % (hex(self.absolute_offset(off))))
        else:
            self._off_long_name_size = False
            self._off_long_name = False

    def __unicode__(self):
        return u"Fileentry @ %s: %s." % (hex(self.offset()), self.name())

    def __str__(self):
        return "Fileentry @ %s: %s." % (hex(self.offset()), self.name())

    def long_name_size(self):
        if self._off_long_name_size:
            return self._off_long_name_size
        elif self._off_long_name:
            return len(self.long_name()) + 2 
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
        else:
            return self.short_name()

class SHITEM_FILEENTRY(Fileentry):
    def __init__(self, buf, offset, parent):
        debug("SHITEM_FILEENTRY @ %s." % (hex(offset)))
        super(SHITEM_FILEENTRY, self).__init__(buf, offset, parent, 0x4)

        self._f("byte", "flags", 0x3); 

    def __unicode__(self):
        return u"SHITEM_FILEENTRY @ %s: %s." % (hex(self.offset()), self.name())

    def __str__(self):
        return "SHITEM_FILEENTRY @ %s: %s." % (hex(self.offset()), self.name())

class ITEMPOS_FILEENTRY(Fileentry):
    def __init__(self, buf, offset, parent):
        debug("ITEMPOS_FILEENTRY @ %s." % (hex(offset)))
        super(ITEMPOS_FILEENTRY, self).__init__(buf, offset, parent, 0x4)

        self._f("word", "size", 0x0) # override
        self._f("word", "flags", 0x2); 

    def __unicode__(self):
        return u"ITEMPOS_FILEENTRY @ %s: %s." % (hex(self.offset()), self.name())

    def __str__(self):
        return "ITEMPOS_FILEENTRY @ %s: %s." % (hex(self.offset()), self.name())

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

    # UNKNOWN1

            type = self.unpack_byte(off + 2)
            if type == SHITEMTYPE.FILE_ENTRY0 or \
               type == SHITEMTYPE.FILE_ENTRY1 or \
               type == SHITEMTYPE.FILE_ENTRY2:
                item = SHITEM_FILEENTRY(self._buf, off, self)

            elif type == SHITEMTYPE.FOLDER_ENTRY:
                item = SHITEM_FOLDERENTRY(self._buf, off, self)

            elif type == SHITEMTYPE.VOLUME_NAME:
                item = SHITEM_VOLUMEENTRY(self._buf, off, self)

            elif type == SHITEMTYPE.NETWORK_VOLUME_NAME0 or \
                 type == SHITEMTYPE.NETWORK_VOLUME_NAME1 or \
                 type == SHITEMTYPE.NETWORK_VOLUME_NAME2 or \
                 type == SHITEMTYPE.NETWORK_VOLUME_NAME3:
                item = SHITEM_NETWORKVOLUMEENTRY(self._buf, off, self)

            elif type == SHITEMTYPE.NETWORK_SHARE:
                item = SHITEM_NETWORKSHAREENTRY(self._buf, off, self)

            elif type == SHITEMTYPE.URI:
                item = SHITEM_URIENTRY(self._buf, off, self)

            elif type == SHITEMTYPE.CONTROL_PANEL:
                item = SHITEM_CONTROLPANELENTRY(self._buf, off, self)

            elif type == SHITEMTYPE.UNKNOWN0:
                item = SHITEM_UNKNOWNENTRY0(self._buf, off, self)

            elif type == SHITEMTYPE.UNKNOWN2:
                item = SHITEM_UNKNOWNENTRY2(self._buf, off, self)

            else:
                debug("Unknown type: %s" % hex(type))
                item = SHITEM(self._buf, off, self)

            yield item
            off += item.size()

    def __unicode__(self):
        return u"SHITEMLIST @ %s." % (hex(self.offset()))

    def __str__(self):
        return "SHITEMLIST @ %s." % (hex(self.offset()))

def get_shellbags(shell_key):
    """
    Given a python-registry RegistryKey object, look for and return a
    list of shellbag items. A shellbag item is a dict with the keys
    (mtime, atime, crtime, path).
    Arguments:
    - `shell_key`: A python-registry Registry object.
    Throws:
    """
    shellbags = []
    bagmru_key = shell_key.subkey("BagMRU")
    bags_key = shell_key.subkey("Bags")

    def shellbag_rec(key, bag_prefix, path_prefix):
        """
        Function to recursively parse the BagMRU Registry key structure.
        Arguments:
        `key`: The current 'BagsMRU' key to recurse into.
        `bag_prefix`: A string containing the current subkey path of 
            the relevant 'Bags' key. It will look something like '1\\2\\3\\4'.
        `path_prefix` A string containing the current human-readable, 
            file system path so far constructed.
        Throws:
        """
        try:
            # First, consider the current key, and extract shellbag items
            slot = key.value("NodeSlot").value()
            for bag in bags_key.subkey(str(slot)).subkeys():
                for value in [value for value in bag.values() if \
                              "ItemPos" in value.name()]:
                    buf = value.value()
                    debug("Slot %s ITEMPOS @ %s" % (str(slot), value.name()))

                    block = Block(buf, 0x0, False)
                    offset = 0x10
                
                    while True:
                        offset += 0x8
                        size = block.unpack_word(offset)
                        if size == 0:
                            break
                        elif size < 0x15:
                            pass
                        else:
                            item = ITEMPOS_FILEENTRY(buf, offset, False)
                            shellbags.append({
                                "path": path_prefix + "\\" + item.name(),
                                "mtime": item.m_date(),
                                "atime": item.a_date(),
                                "crtime": item.cr_date()
                            })
                        offset += size
        except Registry.RegistryValueNotFoundException:
            pass

        # Next, recurse into each BagMRU key
        for value in key.values():
            if not re.match("\d+", value.name()):
                # ignore NodeSlot, etc.
                continue

            l = SHITEMLIST(value.value(), 0, False)
            for item in l.items():
                # assume there is only one entry in the value, or take the last
                # as the path component
                path = path_prefix + "\\" + item.name()
                shellbags.append({
                    "path":  path,
                    "mtime": item.m_date(),
                    "atime": item.a_date(),
                    "crtime": item.cr_date()
                })

            shellbag_rec(key.subkey(value.name()), 
                         bag_prefix + "\\" + value.name(), 
                         path)

    shellbag_rec(bagmru_key, "", "")
    return shellbags

def get_all_shellbags(registry):
    """
    Given a python-registry Registry object, look for and return a
    list of shellbag items. A shellbag item is a dict with the keys
    (mtime, atime, crtime, path).
    Arguments:
    - `registry`: A python-registry Registry object.
    Throws:
    """
    shellbags = []
    paths = [
        # xp
        "Software\\Microsoft\\Windows\\Shell",
        "Software\\Microsoft\\Windows\\ShellNoRoam",
        # win7
        "Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell",
    ]

    for path in paths:
        try:
            debug("Processing: %s" % (path))
            shell_key = registry.open(path)
            new = get_shellbags(shell_key)
            debug("Found %s new shellbags" % (len(new)))
            shellbags.extend(new)
        except Registry.RegistryKeyNotFoundException:
            pass

    return shellbags

def date_safe(d):
    """
    From a Python datetime object, return a corresponding Unix timestamp
    or the epoch timestamp if the datetime object doesn't make sense
    Arguments:
    - `d`: A Python datetime object
    Throws:
    """
    try:
        return int(time.mktime(d.timetuple()))
    except ValueError:
        return int(time.mktime(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))

def shellbag_bodyfile(m, a, cr, path):
    """
    Given the MAC timestamps and a path, return a Bodyfile v3 string entry
    formatted with the data.
    Arguments:
    - `m`: A Python datetime object representing the modified date.
    - `a`: A Python datetime object representing the accessed date.
    - `cr`: A Python datetime object representing the created date.
    - `path`: A string with the entry path.
    Throws:
    """
    modified = date_safe(m)
    accessed = date_safe(a)
    created = date_safe(cr)
    changed = int(time.mktime(datetime.datetime(1970, 1, 1, 0, 0, 0).timetuple()))
    return u"0|Shellbag %s|0|0|0|0|0|%s|%s|%s|%s" % \
                 (path, modified, accessed, changed, created)

def usage():
    return "  USAGE:\n\t%s <Windows Registry file>" % sys.argv[1]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])

    for shellbag in get_all_shellbags(registry):
        try:
            print shellbag_bodyfile(shellbag["mtime"], 
                                    shellbag["atime"], 
                                    shellbag["crtime"], 
                                    shellbag["path"])
        except UnicodeEncodeError:
            warning("Failed printing path: " + str(list(shellbag["path"])))

