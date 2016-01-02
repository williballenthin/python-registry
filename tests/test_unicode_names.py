#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import six
import unittest

from Registry import Registry


class TestRegistryUnicode(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), 'reg_samples', 'UNICODE_TESTS')

    @classmethod
    def is_correct_string(cls, data):
        return (isinstance(data, six.text_type)
                and (data == u""
                     or data.startswith(u"ASCII")
                     or data.startswith(u'UNICODE_JUMBLE_{H~\u2591\xf4\xab}')))

    def test_decoding(self):
        root = Registry.Registry(self.path).root()
        for key in root.subkeys():
            self.assertTrue(self.is_correct_string(key.name()), key.name())
            for value in key.values():
                self.assertTrue(self.is_correct_string(value.name()), value.name())
                val = value.value()
                if isinstance(val, list):
                    for item in val:
                        self.assertTrue(self.is_correct_string(item), item)
                else:
                    self.assertTrue(self.is_correct_string(val), val)

# Run Tests
if __name__ == '__main__':
    unittest.main(verbosity=2)
