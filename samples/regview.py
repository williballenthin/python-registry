#!/usr/bin/python

#    This file is part of python-registry.
#
#    python-registry is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    python-registry is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with python-registry.  If not, see <http://www.gnu.org/licenses/>.


import sys
import wx
from Registry import *

class RegistryTreeCtrl(wx.TreeCtrl):
    def __init__(self, *args, **kwargs):
        super(RegistryTreeCtrl, self).__init__(*args, **kwargs)
        self.Bind(wx.EVT_TREE_ITEM_EXPANDING, self.OnExpandItem)

    def add_registry(self, registry):
        root_key = registry.root()
        root_item = self.AddRoot(root_key.name())
        self.SetPyData(root_item, {"key": root_key,
                                    "has_expanded": False})

        if len(root_key.subkeys()) > 0:
            self.SetItemHasChildren(root_item)

    def _extend(self, item):
        key = self.GetPyData(item)["key"]
        
        for subkey in key.subkeys():
            subkey_item = self.AppendItem(item, subkey.name())
            self.SetPyData(subkey_item, {"key": subkey,
                                         "has_expanded": False})

            if len(subkey.subkeys()) > 0:
                self.SetItemHasChildren(subkey_item)

        self.GetPyData(item)["has_expanded"] = True                

    def OnExpandItem(self, event):
        item = event.GetItem()
        if not item.IsOk():
            item = self.GetSelection()

        if not self.GetPyData(item)["has_expanded"]:
            self._extend(item)

class RegView(wx.Frame):
    def __init__(self, parent, registry):
        super(RegView, self).__init__(parent, -1, "Registry Viewer", size = (400, 600))

        self._tree = RegistryTreeCtrl(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self._tree, 1, wx.EXPAND, 0)
        self.SetAutoLayout(True)
        self.SetSizer(sizer)
        self.Layout()

        self._tree.add_registry(registry)

def usage():
    return "  USAGE:\n\t%s <Windows Registry file>" % (sys.argv[0])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)

    registry = Registry.Registry(sys.argv[1])

    app = wx.App(False)
    frame = RegView(None, registry=registry)
    frame.Show()
    app.MainLoop()

        
        


        








