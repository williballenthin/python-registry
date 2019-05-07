#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime
from decimal import ROUND_HALF_EVEN

import pytest
from Registry.RegistryParse import parse_timestamp, parse_windows_timestamp


def test_parse_windows_timestamp():
    tests = {
        # Rounding error in old floating point calculation, which gave 2016-7-14 10:40:00.041864)
        131132256000418650: datetime(2016, 7, 17, 10, 40, 0, 41865),
        # This actually rounds up to microseconds=041866 using 64-bit floating point arithmetic
        131132256000418654: datetime(2016, 7, 17, 10, 40, 0, 41865),
        # Unix epoch
        116444736000000000: datetime(1970, 1, 1, 0, 0, 0, 0),
        # Rounding up to next second
        116444736009999996: datetime(1970, 1, 1, 0, 0, 1, 0),
        # Rounding the last digit which doesn't fit into datetime.microseconds
        116444736000000006: datetime(1970, 1, 1, 0, 0, 0, 1),
        # round up to even
        116444736000000015: datetime(1970, 1, 1, 0, 0, 0, 2),
        # round down to even
        116444736000000005: datetime(1970, 1, 1, 0, 0, 0, 0),
    }

    for timestamp, expected in tests.items():
        actual = parse_windows_timestamp(timestamp)
        assert expected == actual


# HFS timestamps are seconds + 65535ths of seconds since 1 Jan 1904
HFS_EPOCH = datetime(1904, 1, 1)
HFS_RESOLUTION = 65535

# Mac absolute timestamps are seconds since 1 Jan 2001
MAC_EPOCH = datetime(2001, 1, 1)
MAC_RESOLUTION = 1

# NTFS timestamps are hundreds of nanoseconds since 1 Jan 1601
NTFS_EPOCH = datetime(1601, 1, 1)
NTFS_RESOLUTION = int(1e7)

# UNIX timestamps are seconds since 1 Jan 1970
UNIX_EPOCH = datetime(1970, 1, 1)
UNIX_RESOLUTION = 1

HFS_TESTS = {
    # least HFS timestamp
    0: datetime(1904, 1, 1, 0, 0, 0, 0),
    # least nonzero HFS timestamp
    1: datetime(1904, 1, 1, 0, 0, 0, 15),
    65535: datetime(1904, 1, 1, 0, 0, 1),
    136496402790465: datetime(1969, 12, 31, 11, 59, 59),
    136496402856000: datetime(1969, 12, 31, 12, 0, 0),
    136499233968000: datetime(1970, 1, 1, 0, 0, 0),
    233401598681175: datetime(2016, 11, 8, 20, 1, 45),
    233401598707098: datetime(2016, 11, 8, 20, 1, 45, 395560),
    # greatest "low" timestamp
    281470681743360: datetime(2040, 2, 6, 6, 28, 16),
    514872280424535: datetime(2152, 12, 16, 2, 30, 1),
    # greatest HFS timestamp representable as a datetime
    16743219016895999: datetime(9999, 12, 31, 23, 59, 59, 999985)
}

MAC_TESTS = {
    # least Mac absolute timestamp
    0: datetime(2001, 1, 1, 0, 0, 0),
    # least nonzero Mac absolute timestamp
    1: datetime(2001, 1, 1, 0, 0, 1),
    307828812: datetime(2010, 10, 3, 20, 0, 12),
}

NTFS_TESTS = {
    # least NTFS timestamp
    0: datetime(1601, 1, 1, 0, 0, 0, 0),
    # least nonzero NTFS timestamp
    1: datetime(1601, 1, 1, 0, 0, 0, 0),
    # least nonzero NTFS timestamp which doesn't round to the epoch
    10: datetime(1601, 1, 1, 0, 0, 0, 1),
    131467743999999999: datetime(2017, 8, 9, 17, 46, 40),
    # greatest NTFS timestamp representable as a datetime
    2650467743999999994: datetime(9999, 12, 31, 23, 59, 59, 999999)
}

UNIX_TESTS = {
    # least signed 32-bit UNIX timestamp
    -2147483648: datetime(1901, 12, 13, 20, 45, 52),
    # least nonnegative UNIX timestamp
    0: datetime(1970, 1, 1, 0, 0, 0),
    # least nonzero UNIX timestamp
    1: datetime(1970, 1, 1, 0, 0, 1),
    1516799714: datetime(2018, 1, 24, 13, 15, 14),
    # greatest signed 32-bit UNIX timestamp
    2147483647: datetime(2038, 1, 19, 3, 14, 7)
}

TEST_SETS = [
    (HFS_TESTS, HFS_RESOLUTION, HFS_EPOCH, ROUND_HALF_EVEN),
    (MAC_TESTS, MAC_RESOLUTION, MAC_EPOCH, ROUND_HALF_EVEN),
    (NTFS_TESTS, NTFS_RESOLUTION, NTFS_EPOCH, ROUND_HALF_EVEN),
    (UNIX_TESTS, UNIX_RESOLUTION, UNIX_EPOCH, ROUND_HALF_EVEN)
]

TEST_CONFIGS = []
for tests, resolution, epoch, mode in TEST_SETS:
    for tics, expected in tests.items():
        TEST_CONFIGS.append((expected, tics, resolution, epoch, mode))


@pytest.mark.parametrize('expected,tics,resolution,epoch,mode', TEST_CONFIGS)
def test_parse_timestamp(expected, tics, resolution, epoch, mode):
    actual = parse_timestamp(tics, resolution, epoch, mode=mode)
    assert expected == actual
