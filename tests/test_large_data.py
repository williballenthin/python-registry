#!/usr/bin/python
# -*- coding: utf-8 -*-
import hashlib
import os
import unittest

from Registry import Registry


class TestRegistryLargeData(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'testing', 'reg_samples', 'new_log_1', 'SYSTEM')

    def test_large_data(self):
        root = Registry.Registry(self.path).root()
        value = root.find_key(r'ControlSet001\Control\ProductOptions').value('ProductPolicy')
        data = value.raw_data()
        self.assertEqual(bytes, type(data))
        self.assertEqual(23712, len(data))
        self.assertEqual('7e96f10f77e1c44771d7045c24b94024', hashlib.md5(data).hexdigest())

# Run Tests
if __name__ == '__main__':
    unittest.main(verbosity=2)
