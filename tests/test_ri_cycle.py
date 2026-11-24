#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Regression test for #114: an RI subkey list that references itself
(directly or through another RI list) must not recurse forever.

The hive is built in memory, so no fixture file is needed.
"""
import io
import struct
import unittest

from Registry import Registry
from Registry.RegistryParse import ParseException

HBIN_SIZE = 0x1000
NK_OFFSET = 0x20   # relative to the first HBIN
RI_OFFSET = 0x80


def _cell(data, size):
    data = struct.pack("<i", -size) + data
    return data + b"\x00" * (size - len(data))


def _hive(ri_targets):
    """
    Build a minimal hive whose root key has a single RI subkey list at
    RI_OFFSET. Each entry of `ri_targets` is the HBIN-relative offset of one
    RI list; the list at index i points at ri_targets[i].
    """
    regf = bytearray(0x1000)
    regf[0x0:0x4] = b"regf"
    struct.pack_into("<I", regf, 0x24, NK_OFFSET)
    struct.pack_into("<I", regf, 0x28, HBIN_SIZE)

    hbin = bytearray(HBIN_SIZE)
    hbin[0x0:0x4] = b"hbin"
    struct.pack_into("<I", hbin, 0x8, HBIN_SIZE)

    nk = bytearray(0x4C)
    nk[0x0:0x2] = b"nk"
    struct.pack_into("<H", nk, 0x2, 0x2C)          # root key flags
    struct.pack_into("<I", nk, 0x14, 1)            # subkey count
    struct.pack_into("<I", nk, 0x1C, RI_OFFSET)    # subkey list
    struct.pack_into("<I", nk, 0x24, 0)            # value count
    hbin[NK_OFFSET:NK_OFFSET + 0x60] = _cell(bytes(nk), 0x60)

    offset = RI_OFFSET
    for target in ri_targets:
        ri = b"ri" + struct.pack("<HI", 1, target)
        hbin[offset:offset + 0x10] = _cell(ri, 0x10)
        offset += 0x10

    struct.pack_into("<i", hbin, offset, HBIN_SIZE - offset)  # free remainder
    return io.BytesIO(bytes(regf) + bytes(hbin))


class TestRICycle(unittest.TestCase):
    def test_self_referencing_ri_list(self):
        reg = Registry.Registry(_hive([RI_OFFSET]))
        with self.assertRaises(ParseException):
            reg.root().subkeys()

    def test_mutually_referencing_ri_lists(self):
        reg = Registry.Registry(_hive([RI_OFFSET + 0x10, RI_OFFSET]))
        with self.assertRaises(ParseException):
            reg.root().subkeys()


if __name__ == "__main__":
    unittest.main(verbosity=2)
