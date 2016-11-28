#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import unittest

from Registry.RegistryParse import parse_windows_timestamp


class TestParseTimestamp(unittest.TestCase):
    def test_parse_timestamp(self):
        tests = {
            # Rounding error in old floating point calculation, which gave 2016-7-14 10:40:00.041864)
            131132256000418650: datetime.datetime(2016, 7, 17, 10, 40, 0, 41865),
            # This actually rounds up to microseconds=041866 using 64-bit floating point arithmetic
            131132256000418654: datetime.datetime(2016, 7, 17, 10, 40, 0, 41865),
            # Unix epoch
            116444736000000000: datetime.datetime(1970, 1, 1, 0, 0, 0, 0),
            # Rounding up to next second
            116444736009999996: datetime.datetime(1970, 1, 1, 0, 0, 1, 0),
            # Rounding the last digit which doesn't fit into datetime.microseconds
            116444736000000006: datetime.datetime(1970, 1, 1, 0, 0, 0, 1),
            # round up to even
            116444736000000015: datetime.datetime(1970, 1, 1, 0, 0, 0, 2),
            # round down to even
            116444736000000005: datetime.datetime(1970, 1, 1, 0, 0, 0, 0),
        }

        for timestamp, expected in tests.items():
            actual = parse_windows_timestamp(timestamp)
            self.assertEqual(expected, actual, msg='{}: {}!={}'.format(timestamp, expected, actual))


# Run Tests
if __name__ == '__main__':
    unittest.main(verbosity=2)
