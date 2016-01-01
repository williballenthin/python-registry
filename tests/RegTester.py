#!/usr/bin/python

#    This file is part of python-registry.
#
#   Copyright 2011 Will Ballenthin <william.ballenthin@mandiant.com>
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
from __future__ import unicode_literals

import sys, struct
from Registry import Registry

class Value(object):
    def __init__(self, name, data_type, data):
        self.name = name
        self.data_type = data_type
        self.data = data

class Key(object):
    def __init__(self, name):
        self.name = name
        self.values = []

def parse(f):
    t = f.read()
    h = t.partition("\n")[0]
    if "\xff\xfe\x57\x00\x69\x00" in h: # Windows Registry Editor 5.00
        raise "THIS ISNT SUPPORTED YET"
        try:
            t = t.decode("utf16")
            print("Decoded input file with UTF16 decoder")
        except:
            raise
    elif "Windows Registry Editor Version 5.00" in h:
        t = t.decode("iso-8859-1", "replace")
        print("Decoded input file with ASCII decoder")
    elif "REGEDIT4" in h: # Regedit
        t = t.decode("iso-8859-1", "replace")
        print("Decoded input file with ASCII decoder")
    else:
        print("Unable to parse header")
        sys.exit(-1)

    lines = t.split("\n")

    current_key = False
    current_value  = False
    keys = []

    print("Found " + str(len(lines)) + " lines")

    line_count = 0
    for line in [l.rstrip('\r') for l in lines[1:]]:
        line_count += 1

        if len(line.lstrip(" ")) < 2:
            if current_value:
                current_key.values.append(current_value)
                current_value = False
            keys.append(current_key)
            current_key = False
            continue

        if current_key:
            if current_value:
                real_data = line.lstrip(" ")
                real_data = real_data.replace("\\", "")

                for c in real_data.split(","):
                    try:
                        current_value.data += chr(int(c, 16))
                    except ValueError:
                        continue

            else:
                (name, _, data) = line.partition("=")

                # strip exactly one " mark from either side of the name
                if name[0] == '"':
                    name = name[1:]
                if name[-1] == '"':
                    name = name[:-1]

                if name == "@":
                    name = "(default)"

                if ":" in data and data[0] != '"':
                    real_data = data.partition(":")[2].rstrip("\\") # strip off trailing \ if it exists
                    try:
                        if real_data[-1] == '\\':
                            real_data = real_data[:-2]
                    except IndexError:
                        real_data = ""
                    data_type = data.partition(":")[0]
                else:
                    real_data = data
                    data_value = data.rstrip("\r\n") # strip off one " from both sides

                    if data_value[0] == '"':
                        data_value = data_value[1:]
                    if data_value[-1] == '"':
                        data_value = data_value[:-1]

                    data_value = data_value.replace('\\"', '"')
                    data_value = data_value.replace('\\\\', '\\')

                    data_type = "string"

                if "word" in data_type:
                    data_value = int(real_data, 16)

                if "hex" in data_type:
                    data_value = ""
                    for c in real_data.split(","):
                        try:
                            data_value += chr(int(c, 16))
                        except ValueError:
                            continue

                print_value = data_value
                if "word" in data_type:
                    print_value = str(print_value)
                elif "hex" in data_type:
                    print_value = print_value.decode("ascii", "replace") + ""

                v = Value(name, data_type, data_value)
                
                if  data[-1] == "\\":
                    current_value = v
                else:
                    current_key.values.append(v)
        else:
            name = line.lstrip("[").partition("]")[0]
            current_key = Key(name)

    return keys

def key_long_str(key):
    """
    Prints a long listing of a Registry Key
    """
    ret = ""
    ret += str(key) + "\n"
    
    for s in key.subkeys():
        ret += "\tsubkey: %s\n" % (s.name())

    for v in key.values():
        ret += "\tvalue: %s\n" % (v.name())

    return ret

def usage():
    return "  USAGE:\n\t%s  <.reg file>  <Registry Hive file>" % (sys.argv[0])

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(usage())
        sys.exit(-1)

    f = open(sys.argv[1])
    keys = parse(f)
    print("Parsed .reg file")

    r = Registry.Registry(sys.argv[2])
    print("Parsed Registry file")

    not_found_keys = 0
    incorrect_data = 0
    not_found_values = 0

    for k in [k for k in keys if k]:
        try:
            rk = r.open(k.name.partition("\\")[2])
            for v in k.values:
                if v.name == ".Default":
                    v.name = ""
                try:
                    rv = rk.value(v.name)

                    if rv.value_type() == Registry.RegSZ or \
                            rv.value_type() == Registry.RegExpandSZ:
                        rvv = rv.value().decode("utf8")

                        try:
                            if rvv[-1] == '\x00':
                                rvv = rvv[:-1]
                            if rvv[-1] == '\x00':
                                rvv = rvv[:-1]
                        except IndexError:
                            pass

                        vv = unicode(v.data).partition('\x00')[0]
                        
                        if not rvv == vv:
                            print("DATA VALUE INCORRECT: " + k.name + ":" + v.name)
                            print("                      " + rk.path() + ":" + rv.name())
                            print(key_long_str(rk))
                            print()

                            print("|%s|" % (rvv))
                            print(rvv.__class__.__name__)
                            print(len(rvv))
                            print(list(rvv))
                            print()

                            print("|%s|" % (vv))
                            print(vv.__class__.__name__)
                            print(len(vv))
                            print(list(vv))
                            print()

                            incorrect_data += 1

                    elif rv.value_type() == Registry.RegMultiSZ:
                        vv = v.data.decode("utf16").split('\x00')
                        try:
                            rvv = map(lambda x: x.decode("utf8"), rv.value())
                        except:
                            print("UNABLE TO DECODE UTF8")
                            print("Path", rk.path())
                            print("Name", rv.name())
                            print("Value", rv.value())
                            print()

                            raise

                        for vvv in vv:
                            if vvv not in rvv:
                                print("RegMultiSZ DATA VALUE MISSING: " + vvv)
                                print("Path", rk.path())
                                print("Name", rv.name())
                                print("Value", rv.value())
                                print()

                                print("reg data:", list(v.data))
                                print("Decoded reg  value:", vv)
                                print("Decoded Hive value:", rvv)
                                print()

                                incorrect_data += 1

                    elif rv.value_type() == Registry.RegDWord:
                        vv = v.data
                            
                        rvv = rv.value()
                        if not rvv == vv:
                            print("DWORD INCORRECT: " + str(vv) + " != " + str(rvv))
                            print(list(vv))
                            print("Path", rk.path())
                            print("Name", rv.name())
                            print("Value", rv.value())
                            print()

                            incorrect_data += 1

                    elif rv.value_type() == Registry.RegQWord:
                        vv = struct.unpack("<Q", v.data)[0]
                        rvv = rv.value()
                        if not rvv == vv:
                            print("QWORD INCORRECT: " + str(vv) + " != " + str(rvv))
                            print("Path", rk.path())
                            print("Name", rv.name())
                            print("Value", rv.value())
                            print()

                            incorrect_data += 1

                    elif rv.value_type() == Registry.RegBin or \
                         rv.value_type() == Registry.RegNone:
                        vv = v.data
                        rvv = rv.value()
                        if not rvv == vv:
                            print("BIN INCORRECT path: %s name: %s" % (rk.path(), rv.name()))
                            print("Hive Value Length and Data:", len(rv.value()), list(rv.value()))
                            print("reg  Value Length and Data:", len(v.data), list(v.data))
                            print()

                            incorrect_data += 1

                except Registry.RegistryValueNotFoundException:
                    print("VALUE NOT FOUND: " + k.name + ":" +  v.name)
                    not_found_values += 1

        except Registry.RegistryKeyNotFoundException:
            print("KEY NOT FOUND: " + k.name)
            not_found_keys += 1

    if not_found_keys > 0:
        print("Unable to find %d keys" % (not_found_keys))
    else:
        print("Found all keys")

    if not_found_values > 0:
        print("Unable to find %d values" % (not_found_values))
    else:
        print("Found all values")

    if incorrect_data > 0:
        print("%d incorrect data values" % (incorrect_data))
    else:
        print("All supported data values correct")


