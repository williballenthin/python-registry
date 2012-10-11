#!/bin/python

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

import struct
from datetime import datetime

# Constants
RegSZ = 0x0001
RegExpandSZ = 0x0002
RegBin = 0x0003
RegDWord = 0x0004
RegMultiSZ = 0x0007
RegQWord = 0x000B
RegNone = 0x0000
RegBigEndian = 0x0005
RegLink = 0x0006
RegResourceList = 0x0008
RegFullResourceDescriptor = 0x0009
RegResourceRequirementsList = 0x000A

_global_warning_messages = []
def warn(msg):
    if msg not in _global_warning_messages:
        _global_warning_messages.append(msg)
        print "Warning: %s" % (msg)

def parse_windows_timestamp(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600 )

class RegistryException(Exception):
    """
    Base Exception class for Windows Registry access.
    """

    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(RegistryException, self).__init__()
        self._value = value

    def __str__(self):
        return "Registry Exception: %s" % (self._value)

class RegistryStructureDoesNotExist(RegistryException):
    """
    Exception to be raised when a structure or block is requested which does not exist.
    For example, asking for the ValuesList structure of an NKRecord that has no values
    (and therefore no ValuesList) should result in this exception.
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(RegistryStructureDoesNotExist, self).__init__(value)

    def __str__(self):
        return "Registry Structure Does Not Exist Exception: %s" % (self._value)

class ParseException(RegistryException):
    """
    An exception to be thrown during Windows Registry parsing, such as
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
        return "Registry Parse Exception(%s)" % (self._value)

class UnknownTypeException(RegistryException):
    """
    An exception to be raised when an unknown data type is encountered.
    Supported data types current consist of
     - RegSZ
     - RegExpandSZ
     - RegBin
     - RegDWord
     - RegMultiSZ
     - RegQWord
     - RegNone
     - RegBigEndian
     - RegLink
     - RegResourceList
     - RegFullResourceDescriptor
     - RegResourceRequirementsList
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(UnknownTypeException, self).__init__(value)

    def __str__(self):
        return "Unknown Type Exception(%s)" % (self._value)

class RegistryBlock(object):
    """
    Base class for structure blocks in the Windows Registry.
    A block is associated with a offset into a byte-string.

    All blocks (besides the root) also have a parent member, which refers to
    a RegistryBlock that contains a reference to this block, an is found at a
    hierarchically superior rank. Note, by following the parent links upwards,
    the root block should be accessible (aka. there should not be any loops)
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        self._buf = buf
        self._offset = offset
        self._parent = parent

    def unpack_word(self, offset):
        """
        Returns a little-endian WORD (2 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<H", self._buf, self._offset + offset)[0]

    def unpack_dword(self, offset):
        """
        Returns a little-endian DWORD (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<I", self._buf, self._offset + offset)[0]

    def unpack_int(self, offset):
        """
        Returns a little-endian signed integer (4 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<i", self._buf, self._offset + offset)[0]

    def unpack_qword(self, offset):
        """
        Returns a little-endian QWORD (8 bytes) from the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        """
        return struct.unpack_from("<Q", self._buf, self._offset + offset)[0]

    def unpack_string(self, offset, length):
        """
        Returns a string from the relative offset with the given length.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `length`: The length of the string.
        """
        return struct.unpack_from("<%ds" % (length), self._buf, self._offset + offset)[0]

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

class REGFBlock(RegistryBlock):
    """
    The Windows Registry file header. This block has a length of 4k, although
    only the first 0x200 bytes are generally used.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(REGFBlock, self).__init__(buf, offset, parent)

        _id = self.unpack_dword(0)
        if _id != 0x66676572:
            raise ParseException("Invalid REGF ID")

        _seq1 = self.unpack_dword(0x4)
        _seq2 = self.unpack_dword(0x8)

        if _seq1 != _seq2:
            # the registry was not synchronized
            pass

        # TODO: compute checksum and check

    def major_version(self):
        """
        Get the major version of the Windows Registry file format
        in use as an unsigned integer.
        """
        return self.unpack_dword(0x14)

    def minor_version(self):
        """
        Get the minor version of the Windows Registry file format
        in use as an unsigned integer.
        """
        return self.unpack_dword(0x18)

    def hive_name(self):
        """
        Get the hive name of the open Windows Registry file as a string.
        """
        return self.unpack_string(0x30, 64)

    def last_hbin_offset(self):
        """
        Get the buffer offset of the last HBINBlock as an unsigned integer.
        """
        return self.unpack_dword(0x28)

    def first_key(self):
        first_hbin = self.hbins().next()

        key_offset = first_hbin.absolute_offset(self.unpack_dword(0x24))

        d = HBINCell(self._buf, key_offset, first_hbin)
        return NKRecord(self._buf, d.data_offset(), first_hbin)

    def hbins(self):
        """
        A generator that enumerates all HBIN (HBINBlock) structures in this Windows Registry.
        """
        h = HBINBlock(self._buf, 0x1000, self) # sorry, but 0x1000 is a magic number
        yield h

        while h.has_next():
            h = h.next()
            yield h

class HBINCell(RegistryBlock):
    """
    HBIN data cell. An HBINBlock is continuously filled with HBINCell structures.
    The general structure is the length of the block, followed by a blob of data.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(HBINCell, self).__init__(buf, offset, parent)
        self._size = self.unpack_int(0x0)

    def __str__(self):
        if self.is_free():
            return "HBIN Cell (free) at 0x%x" % (self._offset)
        else:
            return "HBIN Cell at 0x%x" % (self._offset)

    def is_free(self):
        """
        Is the cell free?
        """
        return self._size > 0

    def size(self):
        """
        Size of this cell, as an unsigned integer.
        """
        if self.is_free():
            return self._size
        else:
            return self._size * -1

    def next(self):
        """
        Returns the next HBINCell, which is located immediately after this.
        Note: This will always return an HBINCell starting at the next location
        whether or not the buffer is large enough. The calling function should
        check the offset of the next HBINCell to ensure it does not overrun the
        HBIN buffer.
        """
        try:
            return HBINCell(self._buf, self._offset + self.size(), self.parent())
        except:
            raise RegistryStructureDoesNotExist("HBINCell does not exist at 0x%x" % (self._offset + self.size()))

    def offset(self):
        """
        Accessor for absolute offset of this HBINCell.
        """
        return self._offset

    def data_offset(self):
        """
        Get the absolute offset of the data block of this HBINCell.
        """
        return self._offset + 0x4

    def raw_data(self):
        """
        Get the raw data from the buffer contained by this HBINCell.
        """
        return self._buf[self.data_offset():self.data_offset() + self.size()]

    def data_id(self):
        """
        Get the ID string of the data block of this HBINCell.
        """
        return self.unpack_string(0x4, 2)

    def abs_offset_from_hbin_offset(self, offset):
        """
        Offsets contained in HBIN cells are relative to the beginning of the first HBIN.
        This converts the relative offset into an absolute offset.
        """
        h = self.parent()
        while h.__class__.__name__ != "HBINBlock":
            h = h.parent()

        return h.first_hbin().offset() + offset

    def child(self):
        """
        Make a _guess_ as to the contents of this structure and
        return an instance of that class, or just a DataRecord
        otherwise.
        """
        if self.is_free():
            raise RegistryStructureDoesNotExist("HBINCell is free at 0x%x" % (self.offset()))

        id_ = self.data_id()

        if id_ == "vk":
            return VKRecord(self._buf, self.data_offset(), self)
        elif id_ == "nk":
            return NKRecord(self._buf, self.data_offset(), self)
        elif id_ == "lf":
            return LFRecord(self._buf, self.data_offset(), self)
        elif id_ == "lh":
            return LHRecord(self._buf, self.data_offset(), self)
        elif id_ == "li":
            return LIRecord(self._buf, self.data_offset(), self)
        elif id_ == "ri":
            return RIRecord(self._buf, self.data_offset(), self)
        elif id_ == "sk":
            return SKRecord(self._buf, self.data_offset(), self)
        elif id_ == "db":
            return DBRecord(self._buf, self.data_offset(), self)
        else:
            return DataRecord(self._buf, self.data_offset(), self)

class Record(RegistryBlock):
    """
    Abstract class for Records contained by cells in HBINs
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. This SHOULD be an HBINCell.
        """
        super(Record, self).__init__(buf, offset, parent)

    def abs_offset_from_hbin_offset(self, offset):
        # TODO This violates DRY as this is a redefinition, see HBINCell.abs_offset_from_hbin_offset()
        """
        Offsets contained in HBIN cells are relative to the beginning of the first HBIN.
        This converts the relative offset into an absolute offset.
        """
        h = self.parent()
        while h.__class__.__name__ != "HBINBlock":
            h = h.parent()

        return h.first_hbin().offset() + offset

class DataRecord(Record):
    """
    A DataRecord is a HBINCell that does not contain any further structural data, but
    may contain, for example, the values pointed to by a VKRecord.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.

        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. This should be an HBINCell.
        """
        super(DataRecord, self).__init__(buf, offset, parent)

    def __str__(self):
        return "Data Record at 0x%x" % (self.offset())

class DBIndirectBlock(Record):
    """
    The DBIndirect block is a list of offsets to DataRecords with data
    size up to 0x3fd8.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. This should be an HBINCell.
        """
        super(DBIndirectBlock, self).__init__(buf, offset, parent)

    def __str__(self):
        return "Large Data Block at 0x%x" % (self.offset())

    def large_data(self, length):
        """
        Get the data pointed to by the indirect block. It may be large.
        Return a byte array.
        """
        b = bytearray()
        count = 0
        while length > 0:
            off = self.abs_offset_from_hbin_offset(self.unpack_dword(4 * count))
            size = min(0x3fd8, length)
            b += HBINCell(self._buf, off, self).raw_data()[0:size]

            count += 1
            length -= size
        return b

class DBRecord(Record):
    """
    A DBRecord is a large data block, which is not thoroughly documented.
    Its similar to an inode in the Ext file systems.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. This should be an HBINCell.
        """
        super(DBRecord, self).__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != "db":
            raise ParseException("Invalid DB Record ID")

    def __str__(self):
        return "Large Data Block at 0x%x" % (self.offset())

    def large_data(self, length):
        """
        Get the data described by the DBRecord. It may be large.
        Return a byte array.
        """
        off = self.abs_offset_from_hbin_offset(self.unpack_dword(0x4))
        cell = HBINCell(self._buf, off, self)
        dbi = DBIndirectBlock(self._buf, cell.data_offset(), cell)
        return dbi.large_data(length)

class VKRecord(Record):
    """
    The VKRecord holds one name-value pair.  The data may be one many types,
    including strings, integers, and binary data.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
              This should be an HBINCell.
        """
        super(VKRecord, self).__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != "vk":
            raise ParseException("Invalid VK Record ID")

    def data_type_str(self):
        """
        Get the value data's type as a string
        """
        data_type = self.data_type()
        if data_type == RegSZ:
            return "RegSZ"
        elif data_type == RegExpandSZ:
            return "RegExpandSZ"
        elif data_type == RegBin:
            return "RegBin"
        elif data_type == RegDWord:
            return "RegDWord"
        elif data_type == RegMultiSZ:
            return "RegMultiSZ"
        elif data_type == RegQWord:
            return "RegQWord"
        elif data_type == RegNone:
            return "RegNone"
        elif data_type == RegBigEndian:
            return "RegBigEndian"
        elif data_type == RegLink:
            return "RegLink"
        elif data_type == RegResourceList:
            return "RegResourceList"
        elif data_type == RegFullResourceDescriptor:
            return "RegFullResourceDescriptor"
        elif data_type == RegResourceRequirementsList:
            return "RegResourceRequirementsList"
        else:
            return "Unknown type: %s" % (hex(data_type))

    def __str__(self):
        if self.has_name():
            name = self.name()
        else:
            name = "(default)"

        data = ""
        data_type = self.data_type()
        if data_type == RegSZ or data_type == RegExpandSZ:
            data = self.data()[0:16] + "..."
        elif data_type == RegMultiSZ:
            data = str(len(self.data())) + " strings"
        elif data_type == RegDWord or data_type == RegQWord:
            data = str(hex(self.data()))
        elif data_type == RegNone:
            data = "(none)"
        elif data_type == RegBin:
            data = "(binary)"
        else:
            data = "(unsupported)"

        return "VKRecord(Name: %s, Type: %s, Data: %s) at 0x%x" % (name,
                                                         self.data_type_str(),
                                                         data,
                                                         self.offset())

    def has_name(self):
        """
        Has a name? or perhaps we should use '(default)'
        """
        return self.unpack_word(0x2) != 0

    def has_ascii_name(self):
        """
        Is the name of this value in the ASCII charset?
        Note, this doesnt work, yet... TODO
        """
        if self.unpack_word(0x10) & 1 == 1:
            print "ascii name"
        else:
            print "not ascii name"
        return self.unpack_word(0x10) & 1 == 1

    def name(self):
        """
        Get the name, if it exists. If not, the empty string is returned.
        """
        if not self.has_name():
            return ""
        else:
            name_length = self.unpack_word(0x2)
            return self.unpack_string(0x14, name_length)

    def data_type(self):
        """
        Get the data type of this value data as an unsigned integer.
        """
        return self.unpack_dword(0xC)

    def data_length(self):
        """
        Get the length of this value data.
        """
        return self.unpack_dword(0x4)

    def data_offset(self):
        """
        Get the offset to the raw data associated with this value.
        """
        if self.data_length() < 5 or self.data_length() >= 0x80000000:
            return self.absolute_offset(0x8)
        else:
            return self.abs_offset_from_hbin_offset(self.unpack_dword(0x8))

    def data(self):
        """
        Get the data.  This method will return various types based on the data type.

        RegSZ:
          Return a string containing the data, doing the best we can to convert it
          to ASCII or UNICODE.
        RegExpandSZ:
          Return a string containing the data, doing the best we can to convert it
          to ASCII or UNICODE. The special variables are not expanded.
        RegMultiSZ:
          Return a list of strings.
        RegNone:
          See RegBin
        RegDword:
          Return an unsigned integer containing the data.
        RegQword:
          Return an unsigned integer containing the data.
        RegBin:
          Return a sequence of bytes containing the binary data.
        RegBigEndian:
          Not currently supported. TODO.
        RegLink:
          Not currently supported. TODO.
        RegResourceList:
          Not currently supported. TODO.
        RegFullResourceDescriptor:
          Not currently supported. TODO.
        RegResourceRequirementsList:
          Not currently supported. TODO.
        """
        data_type = self.data_type()
        data_length = self.data_length()
        data_offset = self.data_offset()

        if data_type == RegSZ or data_type == RegExpandSZ:
            if data_length >= 0x80000000:
                # data is contained in the data_offset field
                s = struct.unpack_from("<%ds" % (4), self._buf, data_offset)[0]
            elif 0x3fd8 < data_length < 0x80000000:
                d = HBINCell(self._buf, data_offset, self)
                if d.data_id() == "db":
                    # this should always be the case
                    # but empirical testing does not confirm this
                    s = d.child().large_data(data_length)
                else:
                    s = d.raw_data()[:data_length]
            else:
                d = HBINCell(self._buf, data_offset, self)
                s = struct.unpack_from("<%ds" % (data_length), self._buf, d.data_offset())[0]

            try:
                s = s.decode("utf16").encode("utf8").decode("utf8") # iron out the kinks by
            except UnicodeDecodeError:                              # converting to and back to a Python str
                try:
                    s = s.decode("utf8").encode("utf8").decode("utf8")
                except UnicodeDecodeError:
                    try:
                        s = s.decode("utf8", "replace").encode("utf8").decode("utf8")
                    except:
                        print "Well at this point you are screwed."
                        raise
            s = s.partition('\x00')[0]
            return s
        elif data_type == RegBin or data_type == RegNone:
            if data_length >= 0x80000000:
                data_length -= 0x80000000
                return self._buf[data_offset:data_offset + data_length]
            elif 0x3fd8 < data_length < 0x80000000:
                d = HBINCell(self._buf, data_offset, self)
                if d.data_id() == "db":
                    # this should always be the case
                    # but empirical testing does not confirm this
                    return d.child().large_data(data_length)
                else:
                    return d.raw_data()[:data_length]
            return self._buf[data_offset + 4:data_offset + 4 + data_length]
        elif data_type == RegDWord:
            return self.unpack_dword(0x8)
        elif data_type == RegMultiSZ:
            if data_length >= 0x80000000:
                # this means data_length < 5, so it must be 4, and
                # be composed of completely \x00, so the strings are empty
                return []
            elif 0x3fd8 < data_length < 0x80000000:
                d = HBINCell(self._buf, data_offset, self)
                if d.data_id() == "db":
                    s = d.child().large_data(data_length)
                else:
                    s = d.raw_data()[:data_length]
            else:
                s = self._buf[data_offset + 4:data_offset + 4 + data_length]
            s = s.decode("utf16")
            return s.split("\x00")
        elif data_type == RegQWord:
            d = HBINCell(self._buf, data_offset, self)
            return struct.unpack_from("<Q", self._buf, d.data_offset())[0]
        elif data_type == RegBigEndian:
            warn("Data type RegBigEndian not yet supported")
            return False
        elif data_type == RegLink:
            warn("Data type RegLink not yet supported")
            return False
        elif data_type == RegResourceList:
            warn("Data type RegResourceList not yet supported")
            return False
        elif data_type == RegFullResourceDescriptor:
            warn("Data type RegFullResourceDescriptor not yet supported")
            return False
        elif data_type == RegResourceRequirementsList:
            warn("Data type RegResourceRequirementsList not yet supported")
            return False
        elif data_length < 5 or data_length >= 0x80000000:
            return self.unpack_dword(0x8)
        else:
            raise UnknownTypeException("Unknown VK Record type 0x%x at 0x%x" % (data_type, self.offset()))

class SKRecord(Record):
    """
    Security Record. Contains Windows security descriptor,
    Which defines ownership and permissions for local values
    and subkeys.

    May be referenced by multiple NK records.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. This should be an HBINCell.
        """
        super(SKRecord, self).__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != "sk":
            raise ParseException("Invalid SK Record ID")

        self._offset_prev_sk = self.unpack_dword(0x4)
        self._offset_next_sk = self.unpack_dword(0x8)

    def __str__(self):
        return "SK Record at 0x%x" % (self.offset())

class ValuesList(HBINCell):
    """
    A ValuesList is a simple structure of fixed length pointers/offsets to VKRecords.
    """
    def __init__(self, buf, offset, parent, number):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. The parent of a ValuesList SHOULD be a NKRecord.
        """
        super(ValuesList, self).__init__(buf, offset, parent)
        self._number = number

    def __str__(self):
        return "ValueList(Length: %d) at 0x%x" % (self.parent().values_number(), self.offset())

    def values(self):
        """
        A generator that yields the VKRecords referenced by this list.
        """
        value_item = 0x0

        for _ in range(0, self._number):
            value_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(value_item))

            d = HBINCell(self._buf, value_offset, self)
            v = VKRecord(self._buf, d.data_offset(), self)
            value_item += 4
            yield v

class SubkeyList(Record):
    """
    A base class for use by structures recording the subkeys of Registry key.
    The required overload is self.keys(), which is a generator for all the subkeys (NKRecords).
    The SubkeyList is not meant to be used directly.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. The parent of a SubkeyList SHOULD be a NKRecord.
        """
        super(SubkeyList, self).__init__(buf, offset, parent)

    def __str__(self):
        return "SubkeyList(Length: %d) at 0x%x" % (0, self.offset())

    def _keys_len(self):
        return self.unpack_word(0x2)

    def keys(self):
        """
        A generator that yields the NKRecords referenced by this list.
        The base SubkeyList class returns no NKRecords, since it should not be used directly.
        """
        return

class RIRecord(SubkeyList):
    """
    The RIRecord is a structure linking to structures containing
    a lists of offsets/pointers to subkey NKRecords. It is like a double (or more)
    indirect block.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(RIRecord, self).__init__(buf, offset, parent)

    def __str__(self):
        return "RIRecord(Length: %d) at 0x%x" % (len(self.keys()), self.offset())

    def keys(self):
        """
        A generator that yields the NKRecords referenced by this list.
        ri style entry size.
        """
        key_index = 0x4

        for _ in range(0, self._keys_len()):
            key_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(key_index))
            d = HBINCell(self._buf, key_offset, self)

            try:
                for k in d.child().keys():
                    yield k
            except RegistryStructureDoesNotExist:
                raise ParseException("Unsupported subkey list encountered.")

            key_index += 4

class DirectSubkeyList(SubkeyList):
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(DirectSubkeyList, self).__init__(buf, offset, parent)

    def __str__(self):
        return "DirectSubkeyList(Length: %d) at 0x%x" % (self._keys_len(), self.offset())

    def keys(self):
        """
        A generator that yields the NKRecords referenced by this list.
        Assumes each entry is 0x8 bytes long (lf / lh style).
        """
        key_index = 0x4

        for _ in range(0, self._keys_len()):
            key_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(key_index))

            d = HBINCell(self._buf, key_offset, self)
            yield NKRecord(self._buf, d.data_offset(), self)
            key_index += 8

class LIRecord(DirectSubkeyList):
    """
    The LIRecord is a simple structure containing a list of offsets/pointers
    to subkey NKRecords. It is a single indirect block.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(LIRecord, self).__init__(buf, offset, parent)

    def __str__(self):
        return "LIRecord(Length: %d) at 0x%x" % (self._keys_len(), self.offset())

    def keys(self):
        """
        A generator that yields the NKRecords referenced by this list.
        li style entry size.
        """
        key_index = 0x4

        for _ in range(0, self._keys_len()):
            key_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(key_index))

            d = HBINCell(self._buf, key_offset, self)
            yield NKRecord(self._buf, d.data_offset(), self)
            key_index += 4

class LFRecord(DirectSubkeyList):
    """
    The LFRecord is a simple structure containing a list of offsets/pointers
    to subkey NKRecords.
    The LFRecord also contains a hash for the name of the subkey pointed to
    by the offset, which enables more efficient seaching of the Registry tree.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(LFRecord, self).__init__(buf, offset, parent)
        _id = self.unpack_string(0x0, 2)
        if _id != "lf":
            raise ParseException("Invalid LF Record ID")

    def __str__(self):
        return "LFRecord(Length: %d) at 0x%x" % (self._keys_len(), self.offset())

class LHRecord(DirectSubkeyList):
    """
    The LHRecord is a simple structure containing a list of offsets/pointers
    to subkey NKRecords.
    The LHRecord also contains a hash for the name of the subkey pointed to
    by the offset, which enables more efficient seaching of the Registry tree.
    The LHRecord is analogous to the LFRecord, but it uses a different hashing function.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block.
        """
        super(LHRecord, self).__init__(buf, offset, parent)
        _id = self.unpack_string(0x0, 2)
        if _id != "lh":
            raise ParseException("Invalid LH Record ID")

    def __str__(self):
        return "LHRecord(Length: %d) at 0x%x" % (self._keys_len(), self.offset())

class NKRecord(Record):
    """
    The NKRecord defines the tree-like structure of the Windows Registry.
    It contains pointers/offsets to the ValueList (values associated with the given record),
    and to subkeys.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. This should be a HBINCell.
        """
        super(NKRecord, self).__init__(buf, offset, parent)
        _id = self.unpack_string(0x0, 2)
        if _id != "nk":
            raise ParseException("Invalid NK Record ID")

    def __str__(self):
        classname = self.classname()
        if not self.has_classname():
            classname = "(none)"

        if self.is_root():
            return "Root NKRecord(Class: %s, Name: %s) at 0x%x" % (classname,
                                                                   self.name(),
                                                                   self.offset())
        else:
            return "NKRecord(Class: %s, Name: %s) at 0x%x" % (classname,
                                                              self.name(),
                                                              self.offset())

    def has_classname(self):
        """
        Does this have a classname?
        """
        return self.unpack_dword(0x30) != 0xFFFFFFFF

    def classname(self):
        """
        If this has a classname, get it as a string. Otherwise, return the empty string.
        """
        if not self.has_classname():
            return ""

        classname_offset = self.unpack_dword(0x30)
        classname_length = self.unpack_word(0x4A)

        offset = self.abs_offset_from_hbin_offset(classname_offset)
        d = HBINCell(self._buf, offset, self)
        return struct.unpack_from("<%ds" % (classname_length), self._buf, d.data_offset())[0]

    def timestamp(self):
        """
        Get the modified timestamp as a Python datetime.
        """
        return parse_windows_timestamp(self.unpack_qword(0x4))

    def name(self):
        """
        Return the registry key name as a string.
        """
        name_length = self.unpack_word(0x48)
        return self.unpack_string(0x4C, name_length)

    def path(self):
        """
        Return the full path of the registry key as a string.
        """
        name = ""
        p = self

        name = "\\" + name
        name = p.name()
        while p.has_parent_key():
            p = p.parent_key()
            name = p.name() + "\\" + name
        return name

    def is_root(self):
        """
        Is this a root key?
        """
        return self.unpack_word(0x2) == 0x2C

    def has_parent_key(self):
        """
        Is there a parent key? There should always be a parent key, unless
        this is a root key (see self.is_root())
        """
        if self.is_root():
            return False
        try:
            self.parent_key()
            return True
        except ParseException:
            return False

    def parent_key(self):
        """
        Get the parent_key, which will be an NKRecord.
        """
        offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x10))

        # TODO be careful here in setting the parent of the HBINCell
        d = HBINCell(self._buf, offset, self.parent())
        return NKRecord(self._buf, d.data_offset(), self.parent())

    def sk_record(self):
        """
        Get the security descriptor associated with this NKRecord as an SKRecord.
        """
        offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x2C))

        d = HBINCell(self._buf, offset, self)
        return SKRecord(self._buf, d.data_offset(), d)

    def values_number(self):
        """
        Get the number of values associated with this NKRecord/Key.
        """
        num = self.unpack_dword(0x24)
        if num == 0xFFFFFFFF:
            return 0
        return num

    def values_list(self):
        """
        Get the values as a ValuesList.
        Raises RegistryStructureDoesNotExist if this NKRecord has no values.
        """
        if self.values_number() == 0:
            raise RegistryStructureDoesNotExist("NK Record has no associated values.")

        values_list_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x28))

        d = HBINCell(self._buf, values_list_offset, self)
        return ValuesList(self._buf, d.data_offset(), self, self.values_number())

    def subkey_number(self):
        """
        Get the number of subkeys of this key.
        """
        number = self.unpack_dword(0x14)
        if number == 0xFFFFFFFF:
            return 0
        return number

    def subkey_list(self):
        """
        Get the subkeys of this key as a descendant of SubkeyList.
        Raises RegistryStructureDoesNotExists if this NKRecord does not have any subkeys.
        See NKRecord.subkey_number() to check for the existance of subkeys.
        """
        if self.subkey_number() == 0:
            raise RegistryStructureDoesNotExist("NKRecord has no subkey list at 0x%x" % (self.offset()))

        subkey_list_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x1C))

        d = HBINCell(self._buf, subkey_list_offset, self)
        id_ = d.data_id()

        if id_ == "lf":
            l = LFRecord(self._buf, d.data_offset(), self)
        elif id_ == "lh":
            l = LHRecord(self._buf, d.data_offset(), self)
        elif id_ == "ri":
            l = RIRecord(self._buf, d.data_offset(), self)
        elif id_ == "li":
            l = LIRecord(self._buf, d.data_offset(), self)
        else:
            print id_ + " subkey list"
            raise ParseException("Subkey list with type %s encountered, but not yet supported." % (id_))

        return l

class HBINBlock(RegistryBlock):
    """
    An HBINBlock is the basic allocation block of the Windows Registry.
    It has a length of 0x1000.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent block, which links to this block. The parent of the first HBINBlock
        should be the REGFBlock, and the parents of other HBINBlocks should be the preceeding
        HBINBlocks.
        """
        super(HBINBlock, self).__init__(buf, offset, parent)

        _id = self.unpack_dword(0)
        if _id != 0x6E696268:
            raise ParseException("Invalid HBIN ID")

        self._reloffset_next_hbin = self.unpack_dword(0x8)
        self._offset_next_hbin = self._reloffset_next_hbin + self._offset

    def __str__(self):
        return "HBIN at 0x%x" % (self._offset)

    def first_hbin(self):
        """
        Get the first HBINBlock.
        """
        reloffset_from_first_hbin = self.unpack_dword(0x4)
        return HBINBlock(self._buf, (self.offset() - reloffset_from_first_hbin), self.parent())

    def has_next(self):
        """
        Does another HBINBlock exist after this one?
        """
        regf = self.first_hbin().parent()
        if regf.last_hbin_offset() == self.offset():
            return False

        try:
            HBINBlock(self._buf, self._offset_next_hbin, self.parent())
            return True
        except ParseException:
            return False

    def next(self):
        """
        Get the next HBIN after this one.
        Note: This will blindly attempts to create it regardless of if it exists.
        """
        return HBINBlock(self._buf, self._offset_next_hbin, self.parent())

    def cells(self):
        """
        Get a generator that yields each HBINCell contained in this HBIN.
        """
        c = HBINCell(self._buf, self._offset + 0x20, self)

        while c.offset() < self._offset_next_hbin:
            yield c
            c = c.next()

    def records(self):
        """
        A generator that yields each HBINCell contained in this HBIN.
        These are not necessarily in use, or linked to, from the root key.
        """
        c = HBINCell(self._buf, self._offset + 0x20, self)

        while c.offset() < self._offset_next_hbin:
            yield c
            try:
                c = c.next()
            except RegistryStructureDoesNotExist:
                break
