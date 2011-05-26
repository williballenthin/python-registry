

python-registry
===============

Introduction
------------
python-registry was originally written by Willi Ballenthin,
a forensicator who wanted to access the contents of the 
Windows Registry from his Linux laptop. python-registry 
currently provides read-only access to Windows Registry files, 
such as NTUSER.DAT, userdiff, and SAM. The interface is two-fold:
a high-level interface suitable for most tasks, and a low level 
set of parsing objects and methods which may be used for advanced 
study of the Windows Registry. python-registry is written in pure 
Python, making it portable across all major platforms.

Usage
-----

Most users will find the Registry.Registry module most appropriate. 
The module exposes three classes: the Registry, the RegistryKey, 
and the RegistryValue. The Registry organizes parsing and access 
to the Windows Registry file. The RegistryKey is a convenient 
interface into the tree-like structure of the Windows Registry. 
A RegistryKey may have children RegistryKeys, and may also have 
values associated with it. A RegistryValue can be thought of as 
the tuple (name, datatype, value) associated with a RegistryKey. 
python-registry supports all major datatypes, such as RegSZ, 
RegDWord, and RegBin.

To open a Windows Registry file, its this easy:


  import sys
  from Registry import Registry

  reg = Registry.Registry(sys.argv[1])
  Print all keys in a Registry

  def rec(key, depth=0):
      print "\t" * depth + key.path()
    
      for subkey in key.subkeys():
          rec(subkey, depth + 1)

  rec(reg.root())


Find a key and print all string values


  try:
      key = reg.open("SOFTWARE\\Microsoft\\Windows\\Current Version\\Run")
  except Registry.RegistryKeyNotFoundException:
      print "Couldn't find Run key. Exiting..."
      sys.exit(-1)

  for value in [v for v key.values() \
                     if v.value_type() == Registry.RegSZ or \
                        v.value_type() == Registry.RegExpandSZ]:
      print "%s: %s" % (value.name(), value.value())


Advanced users who wish to study the structure of the Windows
Registry may find the Registry.RegistryParse module useful. 
This module implements all known structures of the Windows Registry, 
with the exception of the big-block data chunks.

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


The source directory for python-registry contains a sample/ 
subdirectory that contains small programs that use python-registry. 
For example, regview.py is a read-only clone of Microsoft Window's 
Regedit, implemented in 200 lines.

Selections of the regview.py source code that are relevant to 
python-registry are included below to highlight how the module may 
be used. 




import sys
import wx
from Registry import Registry

class DataPanel(wx.Panel):
    """Displays the value of a RegistryValue humanely."""
    def __init__(self, *args, **kwargs):
        ...

    def _format_hex(self, data):
        ...

    def display_value(self, value):
        self._sizer.Clear()
        data_type = value.value_type()

        if data_type == Registry.RegSZ or \              # we can manipulate
                data_type == Registry.RegExpandSZ or \   # string and integer
                data_type == Registry.RegDWord or \      # types as expected
                data_type == Registry.RegQWord:
            view = wx.TextCtrl(self, style=wx.TE_MULTILINE)
            view.SetValue(unicode(value.value()))

        elif data_type == Registry.RegMultiSZ:           # RegMultiSZ is simply
            view = wx.ListCtrl(self, style=wx.LC_LIST)   # a list of strings
            for string in value.value():
                view.InsertStringItem(view.GetItemCount(), string)

        elif data_type == Registry.RegBin or \           # binary data is supported
                data_type == Registry.RegNone:           # and formatted nicely here
            view = wx.TextCtrl(self, style=wx.TE_MULTILINE)
            font = wx.Font(8, wx.SWISS, wx.NORMAL, wx.NORMAL, False, u'Courier')
            view.SetFont(font)
            view.SetValue(self._format_hex(value.value()))            

        self._sizer.Add(view, 1, wx.EXPAND)
        self._sizer.Layout()

    def clear_value(self):
        ...

class ValuesListCtrl(wx.ListCtrl):
    def __init__(self, *args, **kwargs):
        ...

    def clear_values(self):
        ...

    def add_value(self, value):
        n = self.GetItemCount()
        self.InsertStringItem(n, value.name())           # column 1: name (string)
        self.SetStringItem(n, 1, value.value_type_str()) # column 2: type (string)
        self.values[value.name()] = value                

    def get_value(self, valuename):
        """This is merely a cache of the Registry model."""
        return self.values[valuename]

class RegistryTreeCtrl(wx.TreeCtrl):
    def __init__(self, *args, **kwargs):
        ...

    def add_registry(self, registry):
        root_key = registry.root()                      # .root() is the first key
        root_item = self.AddRoot(root_key.name() + "(%s)" % (sys.argv[1]))
        self.SetPyData(root_item, {"key": root_key,
                                   "has_expanded": False})

        if len(root_key.subkeys()) > 0:                 # we can easily get children
            self.SetItemHasChildren(root_item)          # by asking for subkeys

    def _extend(self, item):
        """Lazily build the tree as the user requests nodes"""
        key = self.GetPyData(item)["key"]
        
        for subkey in key.subkeys(): 
            subkey_item = self.AppendItem(item, subkey.name())
            self.SetPyData(subkey_item, {"key": subkey,
                                         "has_expanded": False})

            if len(subkey.subkeys()) > 0:
                self.SetItemHasChildren(subkey_item)

        self.GetPyData(item)["has_expanded"] = True                

    def OnExpandKey(self, event):
        item = event.GetItem()
        ...
        if not self.GetPyData(item)["has_expanded"]:
            self._extend(item)

def _expand_into(dest, src):
    ...

class RegView(wx.Frame):
    def __init__(self, parent, registry):
        ...
        self._tree.add_registry(registry)

    def OnKeySelected(self, event):
        item = event.GetItem()
        ...
        key = self._tree.GetPyData(item)["key"]
        ...
        for value in key.values():                 # values are easily accessed
            self._value_list_view.add_value(value) # as lists, or can be retrieved
                                                   # with .value(name) by name
    def OnValueSelected(self, event):
        ...

...

if __name__ == '__main__':
    ...
    registry = Registry.Registry(sys.argv[1])

    app = wx.App(False)                            # standard wxPython app
    frame = RegView(None, registry=registry)       # nothing to see here, except
    frame.Show()                                   # easy construction by filename
    app.MainLoop()
