

python-registry
===============

Introduction
------------
python-registry was originally written by Willi Ballenthin, a 
forensicator who wanted to access the contents of the
Windows Registry from his Linux laptop.  python-registry
currently provides read-only access to Windows Registry files,
such as NTUSER.DAT, userdiff, and SAM.  The package is written
in pure Python, making it portable across all major platforms.


Goals
-----
The main goal of python-registry is to provide a pure Python
interface to the contents of the Windows Registry.  The 
interface is actually two-fold: a high-level interface 
suitable for most tasks, and a low level set of parsing 
objects and methods which may be used for advanced study
of the Windows Registry.


Usage
-----
Most users will find the Registry.Registry module most
appropriate.  The module exposes three classes: the Registry,
the RegistryKey, and the RegistryValue.  The Registry organizes
parsing and access to the Windows Registry file.  The 
RegistryKey is a convenient interface into the tree-like 
structure of the Windows Registry.  A RegistryKey may have
children RegistryKeys, and may also have values associated
with it.  A RegistryValue can be thought of as the tuple
(name, datatype, value) associated with a RegistryKey.  
python-registry supports all major datatypes, such as RegSZ,
RegDWord, and RegBin.


For instance, consider the following:

reg = Registry(myregistryfile) 
key = reg.open("SOFTWARE\\Microsoft\\Windows\\")
for val in key.values():
    print "%s:%d" % (val.name(), val.value_type())

for sub in key:
    print "%s" % (sub.path())


Advanced users who wish to study the structure of the 
Windows Registry may find the Registry.RegistryParse
module useful.  This module implements all known structures 
of the Windows Registry, with the exception of the big-block
data chunks.


Testing
-------
python-registry was developed using Python 2.6.5 on 
Ubuntu Linux.  More importantly, the package was tested against
a small set of Windows XP SP3 Registry files acquired from
one of the author's virtual machines.  The script
testing/RegTester.py will parse the .reg files exported by 
Microsoft Regedit and compare the values parsed by 
python-registry.  This tool can be used to identify 
regressions and deficiencies in the development of
python-registry.


Wanted
------
*) Sample Windows Registry files, especially those containing
   "big-block" instances.
*) Bug reports.
*) Feedback.

python-registry was originally developed to scratch one of
the author's itches.  Now he hopes it can be of use to 
someone outside of his lonely NYC apartment.


License
-------
python-registry is released under the GPLv3.


Sources
-------
Nearly all structure definitions used in python-registry
came from one of two sources:
1) WinReg.txt, by B.H., which may be accessed at:
   http://pogostick.net/~pnh/ntpasswd/WinReg.txt
2) The Windows NT Registry File Format version 0.4, by 
   Timothy D. Morgan, which may be accessed at:
   https://docs.google.com/viewer?url=http%3A%2F%2Fsentinelchicken.com%2Fdata%2FTheWindowsNTRegistryFileFormat.pdf   
Copies of these resources are included in the 
documentation/ directory of the python-registry source.

