#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import six
import unittest
from datetime import datetime

from Registry import Registry

class TestReorganizedValues(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), 'reg_samples', 'REORGANIZED_VALUES_TESTS')

    def test_access_bits(self):
        root = Registry.Registry(self.path).root()
        for key in root.subkeys():
            assert(key._nkrecord.access_bits() == 2)

    def test_timestamp(self):
        timestamp = Registry.Registry(self.path)._regf.reorganized_timestamp()
        self.assertEqual(datetime(2016, 7, 17, 10, 40, 0, 41865), timestamp)

# Run Tests
if __name__ == '__main__':
    unittest.main(verbosity=2)
