#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Regression test for the aliased-DB-segment memory-exhaustion issue.

A crafted hive can declare a ``data_length`` far larger than the file while
pointing every ``DBIndirectBlock`` segment offset at one small cell, so
``large_data()`` reassembles a multi-gigabyte value from a tiny input. The fix
rejects a declared length that cannot fit in the file before the reassembly
loop runs. This test builds such a hive in memory (no large fixture committed)
and asserts the oversized length is rejected while a legitimate length still
parses.
"""
import struct
import tempfile
import os
import unittest

from Registry import Registry
from Registry.RegistryParse import ParseException

HBIN_BASE = 0x1000
ROOT_NK_CELL = 0x1020
VALUE_LIST_CELL = 0x1140
VK_CELL = 0x1180
DB_CELL = 0x1200
DB_INDIRECT_CELL = 0x1240
OFFSETS_START = 0x1244
DATA_CELL = 0x82000
SEGMENT_SIZE = 0x3FD8


def build_aliased_hive(data_length):
    """Build a hive whose single VK value declares ``data_length`` and whose DB
    indirect block aliases one ``SEGMENT_SIZE`` cell for every segment."""
    iterations = (data_length + SEGMENT_SIZE - 1) // SEGMENT_SIZE
    end_of_offsets = OFFSETS_START + iterations * 4
    assert DATA_CELL >= end_of_offsets, "offset region overlaps data cell"

    file_len = DATA_CELL + 4 + SEGMENT_SIZE + 0x1000
    buf = bytearray(file_len)

    def dword(off, value):
        struct.pack_into("<I", buf, off, value & 0xFFFFFFFF)

    def word(off, value):
        struct.pack_into("<H", buf, off, value & 0xFFFF)

    def blob(off, data):
        buf[off:off + len(data)] = data

    # REGF header
    dword(0x00, 0x66676572)                 # "regf"
    dword(0x24, ROOT_NK_CELL - HBIN_BASE)   # root cell offset
    dword(0x28, 0x1000)                     # hbins_size

    # HBIN
    dword(0x1000, 0x6E696268)               # "hbin"
    dword(0x1004, 0)
    dword(0x1008, 0x1000)

    # Root NK
    nk = ROOT_NK_CELL + 4
    blob(nk, b"nk")
    word(nk + 0x02, 0x04)                    # is_root
    dword(nk + 0x24, 1)                      # values_number
    dword(nk + 0x28, VALUE_LIST_CELL - HBIN_BASE)
    struct.pack_into("<i", buf, ROOT_NK_CELL, -(nk - ROOT_NK_CELL + 0x60))

    # Value list
    vl = VALUE_LIST_CELL + 4
    dword(vl, VK_CELL - HBIN_BASE)
    struct.pack_into("<i", buf, VALUE_LIST_CELL, -0x20)

    # VK
    vk = VK_CELL + 4
    blob(vk, b"vk")
    word(vk + 0x02, 0)                       # name length
    dword(vk + 0x04, data_length)            # raw data_length
    dword(vk + 0x08, DB_CELL - HBIN_BASE)    # data offset -> DB cell
    dword(vk + 0x0C, 0x3)                    # RegBin
    struct.pack_into("<i", buf, VK_CELL, -0x30)

    # DB cell
    db = DB_CELL + 4
    blob(db, b"db")
    dword(db + 0x04, DB_INDIRECT_CELL - HBIN_BASE)
    struct.pack_into("<i", buf, DB_CELL, -0x10)

    # DB indirect block: every segment offset aliases DATA_CELL
    struct.pack_into("<i", buf, DB_INDIRECT_CELL, -0x10)
    seg_off = DATA_CELL - HBIN_BASE
    for i in range(iterations):
        dword(OFFSETS_START + 4 * i, seg_off)

    # The single aliased data cell
    struct.pack_into("<i", buf, DATA_CELL, -SEGMENT_SIZE)
    blob(DATA_CELL + 4, b"A" * SEGMENT_SIZE)

    return bytes(buf)


class TestLargeDataAlias(unittest.TestCase):
    def _value(self, data_length):
        hive = build_aliased_hive(data_length)
        with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as f:
            f.write(hive)
            path = f.name
        try:
            reg = Registry.Registry(path)
            return reg.root().values()[0].value()
        finally:
            os.unlink(path)

    def test_oversized_data_length_is_rejected(self):
        # 2 MiB declared against a ~540 KB file: must be rejected before the
        # reassembly loop allocates anything.
        with self.assertRaises(ParseException):
            self._value(0x200000)

    def test_legitimate_length_still_parses(self):
        # A length that fits in the file must parse unchanged.
        value = self._value(0x4000)
        self.assertEqual(0x4000, len(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
