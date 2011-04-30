#!/bin/python
import sys, struct

     

class RegistryException(Exception):
    """
    """
    
    def __init__(self, value):
        """
        
        Arguments:
        - `value`:
        """
        self._value = value

    def __str__(self):
        return "Registry Exception(%s)" % (self._value)
        

class ParseException(RegistryException):
    """
    """
    
    def __init__(self, value):
        """
        
        Arguments:
        - `value`:
        """
        super(ParseException, self).__init__(value)

    def __str__(self):
        return "Registry Parse Exception(%s)" % (self._value)



class RegistryBlock(object):
    """
    """
    
    def __init__(self, buf, offset):
        """
        
        Arguments:
        - `buf`:
        - `offset`:
        """
        self._buf = buf
        self._offset = offset

    def unpack_dword(self, offset):
        return struct.unpack_from("<I", self._buf, self._offset + offset)[0]

    def unpack_int(self, offset):
        return struct.unpack_from("<i", self._buf, self._offset + offset)[0]

    def unpack_qword(self, offset):
        return struct.unpack_from("<Q", self._buf, self._offset + offset)[0]

    def unpack_string(self, offset, length):
        return struct.unpack_from("<%ds" % (length), self._buf, self._offset + offset)[0]

class REGFBlock(RegistryBlock):
    """
    """
    
    def __init__(self, buf, offset):
        """
        
        Arguments:
        - `buf`:
        - `offset`:
        """
        super(REGFBlock, self).__init__(buf, offset)

        _id = self.unpack_dword(0)
        if _id != 0x66676572:
            raise ParseException("Invalid REGF ID")

        _seq1 = self.unpack_dword(0x4)
        _seq2 = self.unpack_dword(0x8)

        if _seq1 != _seq2:
            # the registry was not synchronized
            pass

        _ts = self.unpack_qword(0xC)
        
        _major = self.unpack_dword(0x14)
        _minor = self.unpack_dword(0x18)

        _first_key = self.unpack_dword(0x24)
        _last_hbin = self.unpack_dword(0x28)

        _hive_name = self.unpack_string(0x30, 64)

        # TODO: compute checksum and check

    def hbins(self):
        h = HBINBlock(self._buf, 0x1000)
        yield h

        while h.has_next():
            h = h.next()
            yield h

class HBINCell(RegistryBlock):
    """
    """
    
    def __init__(self, buf, offset):
        """
        
        Arguments:
        - `buf`:
        - `offset`:
        """
        super(HBINCell, self).__init__(buf, offset)
        self._size = self.unpack_int(0x0)

    def is_free(self):
        return self._size < 0

    def next(self):
        if self.is_free():
            size = self._size * -1
        else:
            size = self._size
        return HBINCell(self._buf, self._offset + size)

    def __str__(self):
        if self.is_free():
            return "HBIN Cell (free) at 0x%x" % (self._offset)
        else:
            return "HBIN Cell at 0x%x" % (self._offset)

    def offset(self):
        return self._offset

class HBINBlock(RegistryBlock):
    """
    """
    
    def __init__(self, buf, offset):
        """
        
        Arguments:
        - `buf`:
        - `offset`:
        """
        super(HBINBlock, self).__init__(buf, offset)

        _id = self.unpack_dword(0)
        if _id != 0x6E696268:
            raise ParseException("Invalid HBIN ID")

        _reloffset_from_first_hbin = self.unpack_dword(0x4)
        self._reloffset_next_hbin = self.unpack_dword(0x8)
        self._offset_next_hbin = self._reloffset_next_hbin + self._offset

    def __str__(self):
        return "HBIN at 0x%x" % (self._offset)

    def has_next(self):
        try:
            HBINBlock(self._buf, self._offset_next_hbin)
            return True
        except ParseException:
            return False
            
    def next(self):
 
        return HBINBlock(self._buf, self._offset_next_hbin)

    def cells(self):
        c = HBINCell(self._buf, self._offset + 0x20)

        while c.offset() < self._offset_next_hbin:
            yield c
            c = c.next()

class Registry(object):
    """
    """
    
    def __init__(self, filename):
        """

        Arguments:
        - `filename`:
        """
        self._filename = filename
        with open(filename) as f:
            self._buf = f.read()

        self._regf = REGFBlock(self._buf, 0)

        for h in self._regf.hbins():
            print h
            for c in h.cells():
                print "\t%s" % (c)



if __name__ == '__main__':
    Registry(sys.argv[1])
