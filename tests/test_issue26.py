#!/usr/bin/python
# -*- coding: utf-8 -*-
import unittest

from Registry.RegistryParse import decode_utf16le


# here are the test cases written out with their explanations:
#
# 61 00                 --> 61             --> "a"
# 61 62                 --> 61 62          --> "扡"
# 61 62 00 00           --> 61 62          --> "扡"
# 61 00 61 00 00 00     --> 61 00 61 00    --> "aa"
# 61 00 61 62 00 00     --> 61 00 61 62    --> "a扡"
# 61 00 61 00 00        --> 61 00 61 00    --> "aa"
# 61 00 61 62 00        --> 61 00 61 62    --> "a扡"


class TestIssue26(unittest.TestCase):
    def test_utf16le_kanji_with_nulls(self):
        self.assertEqual(decode_utf16le(b"\x61\x00"), u"a")
        self.assertEqual(decode_utf16le(b"\x61\x62"), u"扡")
        self.assertEqual(decode_utf16le(b"\x61\x62\x00\x00"), u"扡")
        self.assertEqual(decode_utf16le(b"\x61\x00\x61\x00\x00\x00"), u"aa")
        self.assertEqual(decode_utf16le(b"\x61\x00\x61\x62\x00\x00"), u"a扡")
        self.assertEqual(decode_utf16le(b"\x61\x00\x61\x00\x00"), u"aa")
        self.assertEqual(decode_utf16le(b"\x61\x00\x61\x62\x00"), u"a扡")
        self.assertEqual(decode_utf16le(b"W\x00.\x00 \x00E\x00u\x00r\x00o\x00p\x00e\x00 \x00S\x00t\x00a\x00n\x00d\x00a\x00r\x00d\x00 \x00T\x00i\x00m\x00e\x00\x00\x00"), \
                         u"W. Europe Standard Time")


if __name__ == "__main__":
    unittest.main(verbosity=2)
