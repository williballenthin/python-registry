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
from __future__ import absolute_import

from ctypes import c_uint32
from struct import pack
from Registry import RegistryParse

class RegistryLog(object):
    """
    A class for parsing and applying a Windows Registry transaction log file.
    """
    def __init__(self, filelikeobject_primary, filelikeobject_log):
        """
        Constructor.
        Arguments:
        - `filelikeobject_primary`: A file-like object with .read(), .write() and .seek() methods.
              This object shall be writable, it will receive the contents of the recovered hive.
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

        recover = self._regf.recovery_required()
        if recover.recover_header or recover.recover_data:
            raise RegistryParse.NotSupportedException("This transaction log file requires self-healing")

        self._primary_buf = filelikeobject_primary.read(512)
        self._primary = filelikeobject_primary

        self._primary_regf = RegistryParse.REGFBlock(self._primary_buf, 0, False)
        self._hive_flags = None
        self._hive_sequence = None
        self._hbins_size = None

    def reload_primary_regf(self):
        """Fill the _primary_buf and _primary_regf variables again."""
        self._primary.seek(0)
        self._primary_buf = self._primary.read(512)
        self._primary_regf = RegistryParse.REGFBlock(self._primary_buf, 0, False)

    def latest_hive_flags(self):
        """Return the latest hive flags. At present, only one bit mask (0x1) is used."""
        return self._hive_flags

    def latest_hbins_size(self):
        """Return the latest hbins_size."""
        return self._hbins_size

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

    def update_regf_header(self, hive_sequence, hbins_size, hive_flags):
        """
        Update the REGF block of the primary file with the new hive_sequence1, hive_sequence2, hbins_size, and hive_flags.
        Recalculate the checksum and reload the REGF block.
        """

        def pack_dword(num):
            return pack(str("<I"), num)

        self._primary.seek(0x4)
        seqnum = pack_dword(hive_sequence)
        self._primary.write(seqnum) # hive_sequence1
        self._primary.write(seqnum) # hive_sequence2

        self._primary.seek(0x28)
        size = pack_dword(hbins_size)
        self._primary.write(size)

        self._primary.seek(0x90)
        flags = pack_dword(hive_flags)
        self._primary.write(flags)

        self.reload_primary_regf()

        self._primary.seek(0x1FC)
        checksum = pack_dword(self._primary_regf.calculate_checksum())
        self._primary.write(checksum)

        self.reload_primary_regf()

    def recover_hive(self):
        """
        Recover the hive from the transaction log file.
        Returns the sequence number of the last log entry applied or None.
        """
        recover = self._primary_regf.recovery_required()

        if recover.recover_header:
            self._primary.seek(0)
            self._primary.write(self._log_buf[:512])
            self.reload_primary_regf()

        if recover.recover_data:
            for log_entry in self._regf.log_entries():
                for dirty_page_reference, dirty_page in log_entry.dirty_pages_with_references():
                    self.write_dirty_page(dirty_page_reference, dirty_page)

                self._hive_flags = log_entry.hive_flags()
                self._hive_sequence = log_entry.sequence()
                self._hbins_size = log_entry.hbins_size()

            self.update_regf_header(self.latest_hive_sequence(), self.latest_hbins_size(), self.latest_hive_flags())
            return log_entry.sequence()

    def recover_hive_continue(self, expected_sequence):
        """
        Continue the recovery from the second transaction log file.
        Returns the sequence number of the last log entry applied or None.
        """
        if expected_sequence != self._regf.hive_sequence2():
            return None

        for log_entry in self._regf.log_entries():
            for dirty_page_reference, dirty_page in log_entry.dirty_pages_with_references():
                self.write_dirty_page(dirty_page_reference, dirty_page)

            self._hive_flags = log_entry.hive_flags()
            self._hive_sequence = log_entry.sequence()
            self._hbins_size = log_entry.hbins_size()

        self.update_regf_header(self.latest_hive_sequence(), self.latest_hbins_size(), self.latest_hive_flags())
        return log_entry.sequence()
