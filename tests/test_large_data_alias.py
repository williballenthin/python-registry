#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Regression tests using fixed, synthetic aliased-DB-segment hive bytes.

See testing/reg_samples/large_data_alias/README.md for provenance, hashes,
layout and limitations. The tests neither construct nor modify the fixtures.
"""
import hashlib
import os
import unittest

from Registry import Registry
from Registry.RegistryParse import ParseException

FIXTURE_SHA256 = {
    'oversized.hive': '3e1b933aa72839ad9844d5dc321e8a0074fd2c95a277ab564f024a87bde1189c',
    'small-control.hive': '6db19df93a079bea639c65b27703bc0445728eb9a944b0ca755a64422e59e2cc',
}


class TestLargeDataAlias(unittest.TestCase):
    def _value(self, filename):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'testing', 'reg_samples', 'large_data_alias', filename)
        with open(path, 'rb') as f:
            self.assertEqual(FIXTURE_SHA256[filename], hashlib.sha256(f.read()).hexdigest())
        return Registry.Registry(path).root().values()[0].value()

    def test_oversized_data_length_is_rejected(self):
        # A 2 MiB declaration in a 552,924-byte file keeps unpatched runs small.
        with self.assertRaises(ParseException) as cm:
            self._value('oversized.hive')
        self.assertIn('Invalid data length 0x200000 exceeds file size 0x86fdc',
                      str(cm.exception))

    def test_small_aliased_control_still_parses(self):
        # Synthetic aliased control; this is not a well-formed-hive assertion.
        self.assertEqual(b'A' * 0x4000, self._value('small-control.hive'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
