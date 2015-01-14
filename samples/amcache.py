#!/usr/bin/python
#    This file is part of python-registry.
#
#   Copyright 2015 Will Ballenthin <william.ballenthin@mandiant.com>
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
import sys
import logging
import datetime
from collections import namedtuple

import argparse
import unicodecsv
from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp as _parse_windows_timestamp


g_logger = logging.getLogger("amcache")
Field = namedtuple("Field", ["name", "getter"])


def make_value_getter(value_name):
    """ return a function that fetches the value from the registry key """
    def _value_getter(key):
        try:
            return key.value(value_name).value()
        except Registry.RegistryValueNotFoundException:
            return None
    return _value_getter


def make_windows_timestamp_value_getter(value_name):
    """
    return a function that fetches the value from the registry key
      as a Windows timestamp.
    """
    f = make_value_getter(value_name)
    def _value_getter(key):
        try:
            return parse_windows_timestamp(f(key) or 0)
        except ValueError:
            return datetime.datetime.min
    return _value_getter


def parse_unix_timestamp(qword):
    return datetime.datetime.fromtimestamp(qword)


def parse_windows_timestamp(qword):
    try:
        return _parse_windows_timestamp(qword)
    except ValueError:
        return datetime.datetime.min


def make_unix_timestamp_value_getter(value_name):
    """
    return a function that fetches the value from the registry key
      as a UNIX timestamp.
    """
    f = make_value_getter(value_name)
    def _value_getter(key):
        try:
            return parse_unix_timestamp(f(key) or 0)
        except ValueError:
            return datetime.datetime.min
    return _value_getter


UNIX_TIMESTAMP_ZERO = parse_unix_timestamp(0)
WINDOWS_TIMESTAMP_ZERO = parse_windows_timestamp(0)


# via: http://www.swiftforensics.com/2013/12/amcachehve-in-windows-8-goldmine-for.html
#Product Name    UNICODE string
#==============================================================================
#0   Product Name    UNICODE string
#1   Company Name    UNICODE string
#2   File version number only    UNICODE string
#3   Language code (1033 for en-US)  DWORD
#4   SwitchBackContext   QWORD
#5   File Version    UNICODE string
#6   File Size (in bytes)    DWORD
#7   PE Header field - SizeOfImage   DWORD
#8   Hash of PE Header (unknown algorithm)   UNICODE string
#9   PE Header field - Checksum  DWORD
#a   Unknown QWORD
#b   Unknown QWORD
#c   File Description    UNICODE string
#d   Unknown, maybe Major & Minor OS version DWORD
#f   Linker (Compile time) Timestamp DWORD - Unix time
#10  Unknown DWORD
#11  Last Modified Timestamp FILETIME
#12  Created Timestamp   FILETIME
#15  Full path to file   UNICODE string
#16  Unknown DWORD
#17  Last Modified Timestamp 2   FILETIME
#100 Program ID  UNICODE string
#101 SHA1 hash of file


# note: order here implicitly orders CSV column ordering cause I'm lazy
FIELDS = [
    Field("path", make_value_getter("15")),
    Field("sha1", make_value_getter("101")),
    Field("size", make_value_getter("6")),
    Field("file_description", make_value_getter("c")),
    Field("first_run", lambda key: key.timestamp()),
    Field("created_timestamp", make_windows_timestamp_value_getter("12")),
    Field("modified_timestamp", make_windows_timestamp_value_getter("11")),
    Field("modified_timestamp2", make_windows_timestamp_value_getter("17")),
    Field("linker_timestamp", make_unix_timestamp_value_getter("f")),
    Field("product", make_value_getter("0")),
    Field("company", make_value_getter("1")),
    Field("pe_sizeofimage", make_value_getter("7")),
    Field("version_number", make_value_getter("2")),
    Field("version", make_value_getter("5")),
    Field("language", make_value_getter("3")),
    Field("header_hash", make_value_getter("8")),
    Field("pe_checksum", make_value_getter("9")),
    Field("id", make_value_getter("100")),
    Field("switchbackcontext", make_value_getter("4")),
]


ExecutionEntry = namedtuple("ExecutionEntry", map(lambda e: e.name, FIELDS))


def parse_execution_entry(key):
    return ExecutionEntry(**{e.name:e.getter(key) for e in FIELDS})


class NotAnAmcacheHive(Exception):
    pass


def parse_execution_entries(registry):
    try:
        volumes = registry.open("Root\\File")
    except Registry.RegistryKeyNotFoundException:
        raise NotAnAmcacheHive()

    ret = []
    for volumekey in volumes.subkeys():
        for filekey in volumekey.subkeys():
            ret.append(parse_execution_entry(filekey))
    return ret


TimelineEntry = namedtuple("TimelineEntry", ["timestamp", "type", "entry"])


def main():
    parser = argparse.ArgumentParser(
        description="Parse program execution entries from the Amcache.hve Registry hive")
    parser.add_argument("registry_hive", type=str,
                        help="Path to the Amcache.hve hive to process")
    parser.add_argument("-v", action="store_true", dest="verbose",
                        help="Enable verbose output")
    parser.add_argument("-t", action="store_true", dest="do_timeline",
                        help="Output in simple timeline format")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    r = Registry.Registry(args.registry_hive)

    try:
        ee = parse_execution_entries(r)
    except NotAnAmcacheHive:
        g_logging.error("doesn't appear to be an Amcache.hve hive")
        return

    if args.do_timeline:
        entries = []
        for e in ee:
            for t in ["first_run", "created_timestamp", "modified_timestamp",
                    "modified_timestamp2", "linker_timestamp"]:
                ts = getattr(e, t)
                if ts == UNIX_TIMESTAMP_ZERO:
                    continue
                if ts == WINDOWS_TIMESTAMP_ZERO:
                    continue
                if ts == datetime.datetime.min:
                    continue

                entries.append(TimelineEntry(ts, t, e))
        w = unicodecsv.writer(sys.stdout, delimiter="|", quotechar="\"",
                              quoting=unicodecsv.QUOTE_MINIMAL, encoding="utf-8")
        w.writerow(["timestamp", "timestamp_type", "path", "sha1"])
        for e in sorted(entries, key=lambda e: e.timestamp):
            w.writerow([e.timestamp, e.type, e.entry.path, e.entry.sha1])
    else:
        w = unicodecsv.writer(sys.stdout, delimiter="|", quotechar="\"",
                              quoting=unicodecsv.QUOTE_MINIMAL, encoding="utf-8")
        w.writerow(map(lambda e: e.name, FIELDS))
        for e in ee:
            w.writerow(map(lambda i: getattr(e, i.name), FIELDS))


if __name__ == "__main__":
    main()
