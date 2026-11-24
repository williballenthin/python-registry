#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Regression tests for #114: an RI subkey list that references itself
(directly or through another RI list), or points at a non-list cell, must not
recurse forever or raise AttributeError.

The hive bytes are committed fixtures. See
testing/reg_samples/ri_cycle/README.md for provenance, hashes, layout and
limitations. The tests neither construct nor modify the fixtures.
"""
import hashlib
import os
import unittest

from Registry import Registry
from Registry.RegistryParse import ParseException

FIXTURE_SHA256 = {
    'ri-self-reference.hive': '6f14e63654b15bf5ce194133a00a957ba3286fb744f2bf8add5dcfa952692edf',
    'ri-mutual-reference.hive': '51ea82b27fc22cbcb4883f4914613e9ff6040f3c58a79de51f3a7ba9cfdd1861',
    'ri-points-to-nk.hive': 'f1d9a7dd2b5b8f8b3d7e1ded7fe55ee24ded42ce05e97078d63468e01fda6f6e',
}


class TestRICycle(unittest.TestCase):
    def _subkeys(self, filename):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'testing', 'reg_samples', 'ri_cycle', filename)
        with open(path, 'rb') as f:
            self.assertEqual(FIXTURE_SHA256[filename], hashlib.sha256(f.read()).hexdigest())
        return Registry.Registry(path).root().subkeys()

    def test_self_referencing_ri_list(self):
        with self.assertRaises(ParseException):
            self._subkeys('ri-self-reference.hive')

    def test_mutually_referencing_ri_lists(self):
        with self.assertRaises(ParseException):
            self._subkeys('ri-mutual-reference.hive')

    def test_ri_list_pointing_to_non_list(self):
        with self.assertRaises(ParseException):
            self._subkeys('ri-points-to-nk.hive')


if __name__ == "__main__":
    unittest.main(verbosity=2)
