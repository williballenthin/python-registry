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

import sys
import ntpath
from enum import Enum

from . import RegistryParse

RegSZ = 0x0001
RegExpandSZ = 0x0002
RegBin = 0x0003
RegDWord = 0x0004
RegMultiSZ = 0x0007
RegQWord = 0x000B
RegNone = 0x0000
RegBigEndian = 0x0005
RegLink = 0x0006
RegResourceList = 0x0008
RegFullResourceDescriptor = 0x0009
RegResourceRequirementsList = 0x000A
RegFileTime = 0x0010

DEVPROP_MASK_TYPE = 0x00000FFF

class HiveType(Enum):
    UNKNOWN = ""
    NTUSER = "ntuser.dat"
    SAM = "sam"
    SECURITY = "security"
    SOFTWARE = "software"
    SYSTEM = "system"
    USRCLASS = "usrclass.dat"
    BCD = "bcd"
    COMPONENTS = "components"
    DEFAULT = "default"
    SCHEMA = "schema.dat"


class RegistryKeyHasNoParentException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(RegistryKeyHasNoParentException, self).__init__(value)

    def __str__(self):
        return "Registry key has no parent key: %s" % (self._value)


class RegistryKeyNotFoundException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """

        Arguments:
        - `value`:
        """
        super(RegistryKeyNotFoundException, self).__init__(value)

    def __str__(self):
        return "Registry key not found: %s" % (self._value)

class RegistryValueNotFoundException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """

        Arguments:
        - `value`:
        """
        super(RegistryValueNotFoundException, self).__init__(value)

    def __str__(self):
        return "Registry value not found: %s" % (self._value)

class RegistryValue(object):
    """
    This is a high level structure for working with the Windows Registry.
    It represents the 3-tuple of (name, type, value) associated with 
      a registry value.
    """
    def __init__(self, vkrecord):
        self._vkrecord = vkrecord

    def name(self):
        """
        Get the name of the value as a string.
        The name of the default value is returned as "(default)".
        """
        if self._vkrecord.has_name():
            return self._vkrecord.name()
        else:
            return  "(default)"

    def value_type(self):
        """
        Get the type of the value as an integer constant.

        One of:
         - RegSZ = 0x0001
         - RegExpandSZ = 0x0002
         - RegBin = 0x0003
         - RegDWord = 0x0004
         - RegMultiSZ = 0x0007
         - RegQWord = 0x000B
         - RegNone = 0x0000
         - RegBigEndian = 0x0005
         - RegLink = 0x0006
         - RegResourceList = 0x0008
         - RegFullResourceDescriptor = 0x0009
         - RegResourceRequirementsList = 0x000A
        """
        return self._vkrecord.data_type()

    def value_type_str(self):
        """
        Get the type of the value as a string.

        One of:
         - RegSZ
         - RegExpandSZ
         - RegBin
         - RegDWord
         - RegMultiSZ
         - RegQWord
         - RegNone
         - RegBigEndian
         - RegLink
         - RegResourceList
         - RegFullResourceDescriptor
         - RegResourceRequirementsList
        """
        return self._vkrecord.data_type_str()

    def value(self):
        return self._vkrecord.data()

    def raw_data(self):
        return self._vkrecord.raw_data()


class RegistryKey(object):
    """
    A high level structure for use in traversing the Windows Registry.
    A RegistryKey is a node in a tree-like structure.
    A RegistryKey may have a set of values associated with it,
      as well as a last modified timestamp.
    """
    def __init__(self, nkrecord):
        """

        Arguments:
        - `NKRecord`:
        """
        self._nkrecord = nkrecord

    def __str__(self):
        return "Registry Key %s with %d values and %d subkeys" % \
            (self.path(), len(self.values()), len(self.subkeys()))

    def __getitem__(self, key):
        return self.value(key)

    def timestamp(self):
        """
        Get the last modified timestamp as a Python datetime.
        """
        return self._nkrecord.timestamp()

    def name(self):
        """
        Get the name of the key as a string.

        For example, "Windows" if the key path were
        /{hive name}/SOFTWARE/Microsoft/Windows
        See RegistryKey.path() to get the complete key name.
        """
        return self._nkrecord.name()

    def path(self):
        """
        Get the full path of the RegistryKey as a string.
        For example, "/{hive name}/SOFTWARE/Microsoft/Windows"
        """
        return self._nkrecord.path()

    def parent(self):
        """
        Get the parent RegistryKey of this key, or raise
        RegistryKeyHasNoParentException if it does not exist (for example,
        the root key has no parent).
        """
        # there may be a memory inefficiency here, since we create
        # a new RegistryKey from the NKRecord parent key, rather
        # than using the parent of this instance, if it exists.
        try:
            return RegistryKey(self._nkrecord.parent_key())
        except RegistryParse.ParseException:
            raise RegistryKeyHasNoParentException(self.name())

    def subkeys(self):
        """
        Return a list of all subkeys.
        Each element in the list is a RegistryKey.
        If the key has no subkeys, the empty list is returned.
        """
        if self._nkrecord.subkey_number() == 0:
            return []

        l = self._nkrecord.subkey_list()
        return [RegistryKey(k) for k in l.keys()]

    def subkey(self, name):
        """
        Return the subkey with a given name as a RegistryKey.
        Raises RegistryKeyNotFoundException if the subkey with 
          the given name does not exist.
        """
        if self._nkrecord.subkey_number() == 0:
            raise RegistryKeyNotFoundException(self.path() + "\\" + name)

        for k in self._nkrecord.subkey_list().keys():
            if k.name().lower() == name.lower():
                return RegistryKey(k)
        raise RegistryKeyNotFoundException(self.path() + "\\" + name)

    def values(self):
        """
        Return a list containing the values associated with this RegistryKey.
        Each element of the list will be a RegistryValue.
        If there are no values associated with this RegistryKey, then the
        empty list is returned.
        """
        try:
            return [RegistryValue(v) for v in self._nkrecord.values_list().values()]
        except RegistryParse.RegistryStructureDoesNotExist:
            return []

    def value(self, name):
        """
        Return the value with the given name as a RegistryValue.
        Raises RegistryValueNotFoundExceptiono if the value with
          the given name does not exist.
        """
        if name == "(default)":
            name = ""
        try:
            for v in self._nkrecord.values_list().values():
                if v.name().lower() == name.lower():
                    return RegistryValue(v)
        except RegistryParse.RegistryStructureDoesNotExist:
            raise RegistryValueNotFoundException(self.path() + " : " + name)
        raise RegistryValueNotFoundException(self.path() + " : " + name)

    def find_key(self, path):
        """
        Perform a search for a RegistryKey with a specific path.
        """
        if len(path) == 0:
            return self

        (immediate, _, future) = path.partition("\\")
        return self.subkey(immediate).find_key(future)
        
    def values_number(self):
    	"""
    	Return the number of values associated with this key
    	"""
    	return self._nkrecord.values_number()
    	
    def subkeys_number(self):
    	"""
    	Return the number of subkeys associated with this key
    	"""
    	return self._nkrecord.subkey_number()


class Registry(object):
    """
    A class for parsing and reading from a Windows Registry file.
    """
    def __init__(self, filelikeobject):
        """
        Constructor.
        Arguments:
        - `filelikeobject`: A file-like object with a .read() method.
              If a Python string is passed, it is interpreted as a filename,
              and the corresponding file is opened.
        """
        try:
            self._buf = filelikeobject.read()
        except AttributeError:
            with open(filelikeobject, "rb") as f:
                self._buf = f.read()
        self._regf = RegistryParse.REGFBlock(self._buf, 0, False)

    def hive_name(self):
        """Returns the internal file name"""
        return self._regf.hive_name()

    def hive_type(self):
        """Returns the hive type"""
        temp = self.hive_name()
        temp = temp.replace('\\??\\', '')
        temp = ntpath.basename(temp)

        if temp.lower() == HiveType.NTUSER.value:
            return HiveType.NTUSER
        elif temp.lower() == HiveType.SAM.value:
            return HiveType.SAM
        elif temp.lower() == HiveType.SECURITY.value:
            return HiveType.SECURITY
        elif temp.lower() == HiveType.SOFTWARE.value:
            return HiveType.SOFTWARE
        elif temp.lower() == HiveType.SYSTEM.value:
            return HiveType.SYSTEM
        elif temp.lower() == HiveType.USRCLASS.value:
            return HiveType.USRCLASS
        elif temp.lower() == HiveType.BCD.value:
            return HiveType.BCD
        elif temp.lower() == HiveType.COMPONENTS.value:
            return HiveType.COMPONENTS
        elif temp.lower() == HiveType.DEFAULT.value:
            return HiveType.DEFAULT
        elif temp.lower() == HiveType.SCHEMA.value:
            return HiveType.SCHEMA
        else:
            return HiveType.UNKNOWN

    def root(self):
        """
        Return the first RegistryKey in the hive.
        """
        return RegistryKey(self._regf.first_key())

    def open(self, path):
        """
        Return a RegistryKey by full path.
        Subkeys are separated by the backslash character ('\').
        A trailing backslash may or may not be present.
        The hive name should not be included.
        """
        # is the first registry key always the root?
        # are there any other keys at this
        # level? is this the name of the hive?
        return RegistryKey(self._regf.first_key()).find_key(path)

def print_all(key):
    if len(key.subkeys()) == 0:
        print(key.path())
    else:
        for k in key.subkeys():
            print_all(k)

if __name__ == '__main__':
    r = Registry(sys.argv[1])
    print_all(r.root())
