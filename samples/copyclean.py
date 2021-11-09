#!/usr/bin/python
# -*- coding: utf-8 -*-

#    This file is part of python-registry.
#    It tries to copy only used parts of hive file,
#    skipping leftover data in unused parts.
#
#   Copyright 2015 Christian Nilsson <nikize@gmail.com>
#   Copyright 2011 Will Ballenthin <william.ballenthin@mandiant.com>
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

from __future__ import print_function

import sys
import struct
import logging

from Registry import RegistryParse

g_logger = logging.getLogger(__file__)


class Copy(RegistryParse.REGFBlock):
    """
    Parsing of file as a Windows Registry file.
    """
    def __init__(self, filelikeobject, writer):
        """
        Constructor.
        Arguments:
        - `filelikeobject`: A file-like object with a .read() method.
              If a Python string is passed, it is interpreted as a filename,
              and the corresponding file is opened.
        """
        try:
            self._buf = filelikeobject.read()
        except AttributeError:
            with open(filelikeobject, "rb") as f:
                self._buf = f.read()
        self._buflen = len(self._buf)
        self._writer = writer

        super(Copy, self).__init__(self._buf, 0, False)

    def pack_dword(self, offset, *data):
        """
        write little-endian DWORDs (4 bytes) to the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `data`: The data to be written, can be multiple
        """
        g_logger.debug("write dword 0x%08x at offset 0x%08x" % (data[0], self._offset + offset))
        #return struct.pack_into(str("<I"), self._writer, self._offset + offset, *data)
        self._writer.seek(offset)
        self._writer.write(struct.pack(str("<I"), *data))

    def pack_qword(self, offset, *data):
        """
        write little-endian QWORDs (8 bytes) to the relative offset.
        Arguments:
        - `offset`: The relative offset from the start of the block.
        - `data`: The data to be written, can be multiple
        """
        g_logger.debug("write qword 0x%016x at offset 0x%08x" % (data[0], self._offset + offset))
        self._writer.seek(offset)
        self._writer.write(struct.pack(str("<Q"), *data))

    def copy(self):
        idx = 0x0
        xsum = 0
        #Copy header (used part is up to and including name) and recalculate checksum.
        while idx < 0x30+64: #Name starts at offset 0x30 and is max 64 bytes long
            dwd = self.unpack_dword(idx)
            xsum ^= dwd
            #copy fields as dword for unified checksum calculation, even if parts are string.
            self.pack_dword(idx, dwd)
            idx += 0x4
        #write calculated checksum
        self.pack_dword(0x1FC, xsum)

        for hbin in self.hbins():
            offset = hbin.offset()
            g_logger.debug("write %s" % (hbin))
            hbinsize = hbin.unpack_dword(0x8)
            # ensure size is multiple of 4k by writing a zero byte at end of block
            self._writer.seek(offset + hbinsize - 1)
            self._writer.write(bytearray(0x1))

            self.pack_dword(offset + 0x0, hbin.unpack_dword(0x0)) # hbin magic
            self.pack_dword(offset + 0x4, hbin.unpack_dword(0x4)) # offset from first hbin
            self.pack_dword(offset + 0x8, hbinsize)
            self.pack_qword(offset + 0xc, hbin.unpack_qword(0xc)) # Unknown (mostly 0x0)
            self.pack_qword(offset + 0x14, hbin.unpack_qword(0x14)) # timestamp
            self.pack_dword(offset + 0x1c, hbin.unpack_dword(0x1c)) # unknown (mostly 0x0)
            for cell in hbin.cells():
                offset = cell.offset()
                is_free = cell.is_free()
                g_logger.debug("write %s size %i" % (str(cell), cell.size()))
                self.pack_dword(offset + 0x0, cell.unpack_dword(0x0)) # (raw) cell size TODO use int
                if not is_free:
                    self._writer.seek(offset + 0x4)
                    self._writer.write(cell.raw_data())


def usage():
    return "  USAGE:\n\t%s  <Source Hive file> <Destination Hive file>" % (sys.argv[0])

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(usage())
        sys.exit(-1)

    # TODO add parsing of commandline to set log level
    g_logger.setLevel(logging.DEBUG)

    f = open(sys.argv[1], "rb")
    fw = open(sys.argv[2], "wb")

    copy = Copy(f, fw)
    # TODO add checksum and sequence check, exit if incorrect,
    # but make it possible to override from the commandline with -f
    copy.copy()

    f.close()
    fw.close()
