#!/bin/python
import sys, struct

# Constants
RegSZ = 0x0001
ExpandSZ = 0x0002
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
    """
    
    def __init__(self, value):
        """
        
        Arguments:
        - `value`:
        """
        super(RegistryStructureDoesNotExist, self).__init__()

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
    """
    
    def __init__(self, value):
        """
        
        Arguments:
        - `value`:
        """
        super(UnknownTypeException, self).__init__(value)

    def __str__(self):
        return "Unknown Type Exception(%s)" % (self._value)

class RegistryBlock(object):
    """ 
    Base class for structure blocks in the Windows Registry.
    A block is associated with a offset into a byte-string.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
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
        return self._parent

    def offset(self):
        return self._offset

class REGFBlock(RegistryBlock):
    """
    The Windows Registry file header.
    """
    
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
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

        #_ts = self.unpack_qword(0xC)
        
        #_major = self.unpack_dword(0x14)
        #_minor = self.unpack_dword(0x18)

        #_first_key = self.unpack_dword(0x24)
        #_last_hbin = self.unpack_dword(0x28)

        #_hive_name = self.unpack_string(0x30, 64)

        # TODO: compute checksum and check

    def hbins(self):
        h = HBINBlock(self._buf, 0x1000, self)
        yield h

        while h.has_next():
            h = h.next()
            yield h

class HBINCell(RegistryBlock):
    """
    HBIN data cell.
    """    
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
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
        return HBINCell(self._buf, self._offset + self.size(), self.parent())

    def offset(self):
        """
        Accessor for absolute offset of this block.
        """
        return self._offset

    def data_offset(self):
        """
        Get the absolute offset of the data block of this HBINCell.
        """
        return self._offset + 0x4

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
        - `cell`: The parent HBINCell of the record.
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
    """
    
    def __init__(self, buf, offset, parent):
        """
        
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent cell
        """
        super(DataRecord, self).__init__(buf, offset, parent)

    def __str__(self):
        return "Data Record at 0x%x" % (self.offset())
        
class VKRecord(Record):
    """
    """
    
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `cell`: The parent HBINCell of the record.
        """
        super(VKRecord, self).__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != "vk":
            raise ParseException("Invalid VK Record ID")

    def _data_type_str(self):
        data_type = self.data_type()
        if data_type == RegSZ:
            return "RegSZ"
        elif data_type == ExpandSZ:
            return "ExpandSZ"
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
            raise UnknownTypeException("Unknown VK Record type 0x%x at 0x%x" % (data_type, self.offset()))

    def __str__(self):
        if self.has_name():
            name = self.name()
        else:
            name = "(default)"

        data = ""
        if self.data_type() == RegSZ:
            data = self.data()[0:16] + "..."
        else:
            data = "()"

        return "VKRecord(Name: %s, Type: %s, Data: %s) at 0x%x" % (name, 
                                                         self._data_type_str(), 
                                                         data,
                                                         self.offset())

    def has_name(self):
        return self.unpack_word(0x2) != 0

    def has_ascii_name(self):
        # TODO this is NOT correct
        if self.unpack_word(0x10) & 1 == 1:
            print "ascii name"
        else:
            print "not ascii name"
        return self.unpack_word(0x10) & 1 == 1

    def name(self):
        if not self.has_name():
            return ""
        else:
            name_length = self.unpack_word(0x2)
            return self.unpack_string(0x14, name_length)

    def data_type(self):
        return self.unpack_dword(0xC)        

    def data_length(self):
        return self.unpack_dword(0x4)

    def data_offset(self):
        if self.data_length() < 5 or self.data_length() >= 0x80000000:
            return self.absolute_offset(0x8)
        else:
            return self.abs_offset_from_hbin_offset(self.unpack_dword(0x8))
        
    def data(self):
        data_type = self.data_type()
        data_length = self.data_length()
        data_offset = self.data_offset()

        if data_type == RegSZ:
            if data_length >= 0x80000000:
                # data is contained in the data_offset field
                s = struct.unpack_from("<%ds" % (4), self._buf, data_offset)[0]
            else:
                # data is in some hbin-data-cell somewhere
                d = HBINCell(self._buf, data_offset, self)
                s = struct.unpack_from("<%ds" % (data_length), self._buf, d.data_offset())[0]
            try:
                s = s.decode("utf8")
            except UnicodeDecodeError:
                try:
                    s = s.decode("utf16")
                except UnicodeDecodeError:
                    print "Well at this point you are screwed."
                    return s.encode("utf8", errors="replace")
            return s

        elif data_type == ExpandSZ:
            print "ExpandSZ"
        elif data_type == RegBin:
            print "RegBin"
        elif data_type == RegDWord:
            print "RegDWorD"
        elif data_type == RegMultiSZ:
            print "RegMultiSZ"
        elif data_type == RegQWord:
            print "RegQWord"
        elif data_type == RegNone:
            print "RegNone"
        elif data_type == RegBigEndian:
            print "RegBigEndian"
        elif data_type == RegLink:
            print "RegLink"
        elif data_type == RegResourceList:
            print "RegResourceList"
        elif data_type == RegFullResourceDescriptor:
            print "RegFullResourceDescriptor"
        elif data_type == RegResourceRequirementsList:
            print "RegResourceRequirementsList"
        else:
            raise UnknownTypeException("Unknown VK Record type 0x%x at 0x%x" % (data_type, self.offset()))

class SKRecord(Record):
    """
    Security Record. Contains Windows security descriptor, 
    which defines ownership and permissions for local values
    and subkeys.

    May be referenced by multiple NK records.
    """
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent HBINCell of the record.
        """
        super(SKRecord, self).__init__(buf, offset, parent)

        _id = self.unpack_string(0x0, 2)
        if _id != "sk":
            raise ParseException("Invalid SK Record ID")

        self._offset_prev_sk = self.unpack_dword(0x4)
        self._offset_next_sk = self.unpack_dword(0x8)

        #ref_count = self.unpack_dword(0xC)
        #descriptor_size = self.unpack_dword(0x10)
        
    def __str__(self):
        return "SK Record at 0x%x" % (self.offset())

class ValuesList(HBINCell):
    """

    """
    
    def __init__(self, buf, offset, parent, number):
        """
        
        Arguments:
        - `buf`:
        - `offset`:
        - `parent`: The parent of a ValuesList SHOULD be a NKRecord.
        """
        super(ValuesList, self).__init__(buf, offset, parent)
        self._number = number

    def __str__(self):
        return "ValueList(Length: %d) at 0x%x" % (self.parent().values_number(), self.offset())

    def values(self):
        value_item = 0x0

        for _ in range(0, self._number):
            value_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(value_item))

            # TODO really fix the parent here
            d = HBINCell(self._buf, value_offset, self)
            v = VKRecord(self._buf, d.data_offset(), self)
            value_item += 4
            yield v

class NKRecord(Record):
    """
    """
    
    def __init__(self, buf, offset, parent):
        """
        
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
        - `parent`: The parent HBINCell of the record.
        """
        super(NKRecord, self).__init__(buf, offset, parent)
        _id = self.unpack_string(0x0, 2)
        if _id != "nk":
            raise ParseException("Invalid NK Record ID")
        
        _ts = self.unpack_qword(0x4)
        parent_offset = self.unpack_dword(0x10)
        subkeys_number = self.unpack_dword(0x14)
        subkey_lf_offset = self.unpack_dword(0x1C)


        sk_record_offset = self.unpack_dword(0x2C)
        
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
        return self.unpack_dword(0x30) != 0xFFFFFFFF

    def classname(self):
        if not self.has_classname():
            return ""

        classname_offset = self.unpack_dword(0x30)
        classname_length = self.unpack_word(0x4A)

        offset = self.abs_offset_from_hbin_offset(classname_offset)
        # TODO find the correct HBIN
        d = HBINCell(self._buf, offset, self.parent())
        return struct.unpack_from("<%ds" % (classname_length), self._buf, d.data_offset())[0]

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

        name = "/" + name
        name = p.name()
        while p.has_parent_key():
            p = p.parent_key()
            name = p.name() + "/" + name
        return name

    def is_root(self):
        return self.unpack_word(0x2) == 0x2C

    def has_parent_key(self):
        if self.is_root():
            return False
        try:
            self.parent_key()
            return True
        except ParseException:
            return False

    def parent_key(self):
        offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x10))

        # TODO find the correct HBIN
        d = HBINCell(self._buf, offset, self.parent())
        return NKRecord(self._buf, d.data_offset(), d)

    def sk_record(self):
        offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x2C))

        # TODO find the correct HBIN
        d = HBINCell(self._buf, offset, self.parent())
        return SKRecord(self._buf, d.data_offset(), d)

    def values_number(self):
        num = self.unpack_dword(0x24)        
        if num == 0xFFFFFFFF:
            return 0
        return num

    def values_list(self):
        if self.values_number() == 0:
            raise RegistryStructureDoesNotExist("NK Record has no associated values.")

        values_list_offset = self.abs_offset_from_hbin_offset(self.unpack_dword(0x28))
        
        # TODO fix parent here
        d = HBINCell(self._buf, values_list_offset, self.parent())
        # TODO I'm making a mess of the parent attribute here (parent should be `d`)
        return ValuesList(self._buf, d.data_offset(), self)

class HBINBlock(RegistryBlock):
    """
    """
    
    def __init__(self, buf, offset, parent):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing Windows Registry file.
        - `offset`: The offset into the buffer at which the block starts.
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
        reloffset_from_first_hbin = self.unpack_dword(0x4)
        return HBINBlock(self._buf, (self.offset() - reloffset_from_first_hbin), self.parent())

    def has_next(self):
        """
        Does another HBIN exist after this one?
        """
        try:
            HBINBlock(self._buf, self._offset_next_hbin, self.parent())
            return True
        except ParseException:
            return False
            
    def next(self):
        """
        Get the next HBIN after this one. 
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
        Get a generator that yields each Record contained in this HBIN.
        """
        c = HBINCell(self._buf, self._offset + 0x20, self)

        while c.offset() < self._offset_next_hbin:
            if c.is_free():
                r = c
            elif c.data_id() == "vk":
                r = VKRecord(self._buf, c.data_offset(), c)

            elif c.data_id() == "nk":
                r = NKRecord(self._buf, c.data_offset(), c)

            elif c.data_id() == "lf":
                r = c
                print "lf"

            elif c.data_id() == "lh":
                r = c
                print "lh"

            elif c.data_id() == "li":
                r = c
                print "li"

            elif c.data_id() == "ri":
                r = c
                print "ri"

            elif c.data_id() == "sk":
                r = SKRecord(self._buf, c.data_offset(), c)
            else:
                r = DataRecord(self._buf, c.data_offset(), c)

            yield r
            c = c.next()

class Registry(object):
    """
    A class for parsing and reading from a Windows Registry file.
    """
    
    def __init__(self, filename):
        """
        Constructor.
        Arguments:
        - `filename`: A string containing the filename of the Windows Registry file, such as
        NTUSER.DAT.
        """
        self._filename = filename
        with open(filename) as f:
            self._buf = f.read()

        self._regf = REGFBlock(self._buf, 0, False)

        n = False
        for h in self._regf.hbins():
            print h
            for c in h.records():
                if c.__class__.__name__ == "NKRecord" and c.values_number() > 0:
                    n = c
                    print c.values_number()
                print "\t%s" % (c)

        print "---"

        m = n
        print m        
        while m.has_parent_key():
            m = m.parent_key()
            print m

        print "---"
        
        print n
        print n.path()
        print n.sk_record()
        print n.values_list()

        for v in n.values_list().values():
            print v


if __name__ == '__main__':
    Registry(sys.argv[1])
