#!/usr/bin/python
# -*- coding: utf-8 -*-
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


def main(args):
    assert(decode_utf16le("\x61\x00") == u"a")
    assert(decode_utf16le("\x61\x62") == u"扡")
    assert(decode_utf16le("\x61\x62\x00\x00") == u"扡")
    assert(decode_utf16le("\x61\x00\x61\x00\x00\x00") == u"aa")
    assert(decode_utf16le("\x61\x00\x61\x62\x00\x00") == u"a扡")
    assert(decode_utf16le("\x61\x00\x61\x00\x00") == u"aa")
    assert(decode_utf16le("\x61\x00\x61\x62\x00") == u"a扡")
    print "Pass"

if __name__ == "__main__":
    import sys
    main(sys.argv)

