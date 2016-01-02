#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import unittest

from Registry import Registry

EXPECTED_MD5 = "0f8f1276f2a4fafc03b2a31775898800"
REG_KEY = "TimeZoneKeyName"
REG_EXPECTED_VALUE = u"W. Europe Standard Time"


class TestIssue22(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(os.path.dirname(__file__), "reg_samples", "issue22.hive")

        import hashlib
        md5 = hashlib.md5()
        with open(self.path, 'rb') as file:
            md5.update(file.read())

        self.assertEqual(md5.hexdigest(), EXPECTED_MD5, \
               "Please use the SYSTEM hive with MD5 %s, got %s" % (EXPECTED_MD5, md5.hexdigest()))

    def test_regsz_value(self):
        reg = Registry.Registry(self.path)
        reg_key = reg.root()
        reg_val = reg_key.value(REG_KEY)
        self.assertEqual(reg_val.value(), REG_EXPECTED_VALUE, \
               "Expected: %s Got: %s (length: %d)" % (REG_EXPECTED_VALUE, reg_val.value(), len(reg_val.value())))


if __name__ == "__main__":
    unittest.main(verbosity=2)
