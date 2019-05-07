#!/bin/python
# 
# This implements the composite value types used in settings.dat registry hive
# used to store AppContainer settings in Windows Apps aka UWP.
# 
# ApplicationDataCompositeValue class is documented here:
# https://docs.microsoft.com/en-us/uwp/api/windows.storage.applicationdatacompositevalue
#
# The internals of types, values and structures had to be reverse engineered.
#
# Copyright (c) 2019 Yogesh Khatri <yogesh@swiftforensics.com> 
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from __future__ import print_function
from __future__ import unicode_literals

from datetime import datetime, timedelta
from uuid import UUID
import binascii
import struct

REG_COMPOSITE_TYPE = 0x100 
# When used in registry to denote value type, the REG_COMPOSITE_TYPE is or'd with one of the 
# values below. Example: RegUInt8 will be (REG_COMPOSITE_TYPE | RegUint8)
# In the serialized ApplicationDataCompositeValue stream, the REG_COMPOSITE_TYPE is not present.  
RegUint8 = 0x001
RegInt16 = 0x002
RegUint16 = 0x003
RegInt32 = 0x004
RegUint32 = 0x005
RegInt64 = 0x006
RegUint64 = 0x007
RegFloat = 0x008 # aka Single
RegDouble = 0x009
RegUnicodeChar = 0x00A
RegBoolean = 0x00B
RegUnicodeString = 0x00C
RegCompositeValue = 0x00D # Application Data Composite Value (Dictionary Object) 
RegDateTimeOffset = 0x00E # Date as FILETIME
RegTimeSpan = 0x00F #  Span in 100ns ticks 
RegGUID = 0x010
RegUnk111 = 0x011
RegUnk112 = 0x012
RegUnk113 = 0x013
RegBytesArray = 0x014
RegInt16Array = 0x015
RegUint16Array = 0x016
RegInt32Array = 0x017
RegUInt32Array = 0x018
RegInt64Array = 0x019
RegUInt64Array = 0x01A
RegFloatArray = 0x01B
RegDoubleArray = 0x01C
RegUnicodeCharArray = 0x01D
RegBooleanArray = 0x01E
RegUnicodeStringArray = 0x01F

def parse_windows_timestamp(qword):
    # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
    return datetime.utcfromtimestamp(float(qword) * 1e-7 - 11644473600 )

def ReadUnicodeStringArray(buf):
    """Read a buffer containing an array of struct { int size; wchar string[size]; }
       Returns a list of utf8 encoded strings
    """
    strings = []
    buf_len = len(buf)
    pos = 0
    while pos < buf_len:
        item_byte_len = struct.unpack_from(str("<I"), buf, pos)[0]
        pos += 4
        strings.append(buf[pos:pos+(item_byte_len)].decode('utf-16').rstrip('\0'))
        pos += item_byte_len
    return strings

def ReadGuid(buf):
    guid = UUID(bytes_le=buf[0:16])
    return guid

def ParseAppDataCompositeValue(item_type, data, data_size):
    """
    Reads an individual Composite type entry from buffer
    Arguments:
        - `item_type`: composite data type (from registry value type)
        - `data`: Byte string containing a single CompositeData object
        - `data_size`: size of data
    """
    value = None
    if   item_type == RegUint8: value = struct.unpack_from(str("<B"), data, 0)[0]
    elif item_type == RegInt16: value = struct.unpack_from(str("<h"), data, 0)[0]
    elif item_type == RegUint16: value = struct.unpack_from(str("<H"), data, 0)[0]
    elif item_type == RegInt32: value = struct.unpack_from(str("<i"), data, 0)[0]
    elif item_type == RegUint32: value = struct.unpack_from(str("<I"), data, 0)[0]
    elif item_type == RegInt64: value = struct.unpack_from(str("<q"), data, 0)[0]
    elif item_type == RegUint64: value = struct.unpack_from(str("<Q"), data, 0)[0]
    elif item_type == RegFloat: value = struct.unpack_from(str("<f"), data, 0)[0]
    elif item_type == RegDouble: value = struct.unpack_from(str("<d"), data, 0)[0]
    elif item_type == RegUnicodeChar: value = data[0:2].decode('utf-16')
    elif item_type == RegBoolean: value = True if data[0:1] != b'\x00' else False
    elif item_type == RegUnicodeString: value = data.decode('utf-16')
    elif item_type == RegCompositeValue: value = ParseAppDataCompositeStream(data)
    elif item_type == RegDateTimeOffset: value = parse_windows_timestamp(struct.unpack_from(str("<Q"), data, 0)[0])
    elif item_type == RegTimeSpan: value = timedelta(seconds= 10e-8 * struct.unpack_from(str("<Q"), data, 0)[0])
    elif item_type == RegGUID: value = ReadGuid(data)
    #elif item_type in ( RegUnk111, RegUnk112, RegUnk113): value = "UNKNOWN TYPE"
    elif item_type == RegBytesArray: value = struct.unpack_from(str("<{}B").format(data_size), data, 0)
    elif item_type == RegInt16Array: value = struct.unpack_from(str("<{}h").format(data_size//2), data, 0)
    elif item_type == RegUint16Array: value = struct.unpack_from(str("<{}H").format(data_size//2), data, 0)
    elif item_type == RegInt32Array: value = struct.unpack_from(str("<{}i").format(data_size//4), data, 0)
    elif item_type == RegUInt32Array: value = struct.unpack_from(str("<{}I").format(data_size//4), data, 0)
    elif item_type == RegInt64Array: value = struct.unpack_from(str("<{}q").format(data_size//8), data, 0)
    elif item_type == RegUInt64Array: value = struct.unpack_from(str("<{}Q").format(data_size//8), data, 0)
    elif item_type == RegFloatArray: value = struct.unpack_from(str("<{}f").format(data_size//4), data, 0)
    elif item_type == RegDoubleArray: value = struct.unpack_from(str("<{}d").format(data_size//8), data, 0)
    elif item_type == RegUnicodeCharArray: value = data.decode('utf-16')
    elif item_type == RegBooleanArray: value = [True if data[x:x+1] != b'\x00' else False for x in range(data_size)]
    elif item_type == RegUnicodeStringArray: value = ReadUnicodeStringArray(data)
    else:
        print("UNKNOWN TYPE FOUND 0x{:X} data={} \nPlease report to developers!".format(item_type, str(data)))
        value = str(data)
    return value

def ParseAppDataCompositeStream(buf):
    """
    Read a buffer containing an ApplicationDataCompositeData binary object 
    and returns a dictionary of items present.
    Arguments:
        - `buf`: Byte string containing the serialized ApplicationDataCompositeData object
    """
    composite_data = {}
    buf_len = len(buf)
    pos = 0
    item_pos = 0
    while pos < buf_len:
        item_byte_len, item_type, item_name_len = struct.unpack_from(str("<III"), buf, pos)
        item_pos = pos
        pos += 12
        item_name = buf[pos:pos+item_name_len*2].decode('utf-16')
        pos += (item_name_len + 1) * 2
        data_size = item_byte_len - 12 - (item_name_len + 1) * 2
        data = buf[pos:pos+data_size]
        value = ParseAppDataCompositeValue(item_type, data, data_size)
        composite_data[item_name] = value

        pos = item_pos + item_byte_len
        if pos % 8: # alignment to 8 byte boundary
            pos += (8 - (pos % 8))
        
    return composite_data
