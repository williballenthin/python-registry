#!/bin/python

#    This file is part of python-registry.
#
#   Copyright 2011, 2012 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import print_function

from ctypes import c_uint32
from . import RegistryParse

class RegistryLog(object):
    """
    A class for parsing and applying a Windows Registry transaction log file.
    """
    def __init__(self, filelikeobject_primary, filelikeobject_log):
        """
        Constructor.
        Arguments:
        - `filelikeobject_primary`: A file-like object with .read(), .write() and .seek() methods.
        - `filelikeobject_log`: A file-like object with a .read() method.
              If a Python string is passed, it is interpreted as a filename,
              and the corresponding file is opened.
        """
        try:
            self._log_buf = filelikeobject_log.read()
        except AttributeError:
                with open(filelikeobject_log, "rb") as f:
                    self._log_buf = f.read()

        self._regf = RegistryParse.REGFBlock(self._log_buf, 0, False)

        if self._regf.is_old_transaction_log_file():
            raise RegistryParse.NotSupportedException("Old transaction log files are not supported")

        if self._regf.is_primary_file():
            raise RegistryParse.ParseException("Cannot load a primary file as a transaction log file")

        if not self._regf.is_new_transaction_log_file():
            raise RegistryParse.NotSupportedException("Unknown file type")

        if self._regf.clustering_factor() != 1:
            raise RegistryParse.NotSupportedException("Clustering factor not equal to 1 is not supported")

        recover_header, recover_data = self._regf.recovery_required()
        if recover_header or recover_data:
            raise RegistryParse.NotSupportedException("This transaction log file requires self-healing")

        self._primary_buf = filelikeobject_primary.read(512)
        self._primary = filelikeobject_primary

        self._primary_regf = RegistryParse.REGFBlock(self._primary_buf, 0, False)
        self._hive_flags = None
        self._hive_sequence = None

    def latest_hive_flags(self):
        """Return the latest hive flags. At present, only one bit mask is used."""
        return self._hive_flags

    def latest_hive_sequence(self):
        """Return the latest hive_sequence1 (the same as hive_sequence2 after recovery)."""
        return self._hive_sequence

    def first_log_sequence(self):
        """Returns the first log sequence number."""
        return self._regf.hive_sequence2()

    def is_eligible_log(self):
        """Check if this log is eligible for the primary file."""
        if not self._primary_regf.validate_checksum():
            return True

        if self.first_log_sequence() >= self._primary_regf.hive_sequence2():
            return True

        return False

    def is_starting_log(self, another_log_file):
        """
        When the dual-logging scheme is used, check if this log shall be applied first.
        Another RegistryLog instance is checked against this one.
        """
        another_seqnum = another_log_file.first_log_sequence()
        this_seqnum = self.first_log_sequence()
        if this_seqnum >= another_seqnum:
            delta = this_seqnum - another_seqnum
            starting = False
        else:
            delta = another_seqnum - this_seqnum
            starting = True

        if c_uint32(delta).value <= 0x7FFFFFFF:
            return starting
        else:
            # Sequence numbers did overflow.
            return not starting

    def write_dirty_page(self, dirty_page_reference, dirty_page):
        """Write a dirty page to the primary file."""
        offset_primary = dirty_page_reference.offset() + self._primary_regf.first_hbin_offset()
        size = dirty_page_reference.size()
        dirty_data = dirty_page.data()
        self._primary.seek(offset_primary)
        self._primary.write(dirty_data)

    def recover_hive(self):
        """Recover the hive from the transaction log file."""
        recover_header, recover_data = self._primary_regf.recovery_required()

        if recover_data:
            for log_entry in self._regf.log_entries():
                for dirty_page_reference, dirty_page in log_entry.dirty_pages_with_references():
                    self.write_dirty_page(dirty_page_reference, dirty_page)

                self._hive_flags = log_entry.hive_flags()
                self._hive_sequence = log_entry.sequence()

        return log_entry.sequence()

    def recover_hive_continue(self, expected_sequence):
        """Continue the recovery from the second transaction log file."""
        if expected_sequence != self._regf.hive_sequence2():
            return None

        for log_entry in self._regf.log_entries():
            for dirty_page_reference, dirty_page in log_entry.dirty_pages_with_references():
                self.write_dirty_page(dirty_page_reference, dirty_page)

            self._hive_flags = log_entry.hive_flags()
            self._hive_sequence = log_entry.sequence()

        return log_entry.sequence()
