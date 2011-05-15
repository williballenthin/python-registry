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

def nop(*args, **kwargs):
    pass

class DataPanel(wx.Panel):
    def __init__(self, *args, **kwargs):
        super(DataPanel, self).__init__(*args, **kwargs)
        self._sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self._sizer)

    def _format_hex(self, data):
        """
        see http://code.activestate.com/recipes/142812/
        """
        FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

        def dump(src, length=16):
            N=0; result=''
            while src:
                s,src = src[:length],src[length:]
                hexa = ' '.join(["%02X"%ord(x) for x in s])
                s = s.translate(FILTER)
                result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
                N+=length
            return result
        return dump(data)

    def display_value(self, value):
        self._sizer.Clear()
        data_type = value.value_type()

        if data_type == Registry.RegSZ or \
                data_type == Registry.ExpandSZ or \
                data_type == Registry.RegDWord or \
                data_type == Registry.RegQWord:
            view = wx.TextCtrl(self, style=wx.TE_MULTILINE)
            view.SetValue(unicode(value.value()))

        elif data_type == Registry.RegMultiSZ:
            view = wx.ListCtrl(self, style=wx.LC_LIST)
            for string in value.value():
                view.InsertStringItem(view.GetItemCount(), string)

        elif data_type == Registry.RegBin or \
                data_type == Registry.RegNone:
            view = wx.TextCtrl(self, style=wx.TE_MULTILINE)
            font = wx.Font(8, wx.SWISS, wx.NORMAL, wx.NORMAL, False, u'Courier')
            view.SetFont(font)
            view.SetValue(self._format_hex(value.value()))            

        self._sizer.Add(view, 1, wx.EXPAND)
        self._sizer.Layout()

    def clear_value(self):
        self._sizer.Clear()
        self._sizer.Add(wx.Panel(self, -1), 1, wx.EXPAND)
        self._sizer.Layout()

class ValuesListCtrl(wx.ListCtrl):
    def __init__(self, *args, **kwargs):
        super(ValuesListCtrl, self).__init__(*args, **kwargs)
        self.InsertColumn(0, "Value name")
        self.InsertColumn(1, "Value type")
        self.SetColumnWidth(1, 100)
        self.SetColumnWidth(0, 300) 
        self.values = {}

    def clear_values(self):
        self.DeleteAllItems()
        self.values = {}

    def add_value(self, value):
        n = self.GetItemCount()
        self.InsertStringItem(n, value.name())
        self.SetStringItem(n, 1, value.value_type_str())     
        self.values[value.name()] = value

    def get_value(self, valuename):
        return self.values[valuename]

class RegistryTreeCtrl(wx.TreeCtrl):
    def __init__(self, *args, **kwargs):
        super(RegistryTreeCtrl, self).__init__(*args, **kwargs)
        self.Bind(wx.EVT_TREE_ITEM_EXPANDING, self.OnExpandKey)


    def add_registry(self, registry):
        root_key = registry.root()
        root_item = self.AddRoot(root_key.name() + "(%s)" % (sys.argv[1]))
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

    def OnExpandKey(self, event):
        item = event.GetItem()
        if not item.IsOk():
            item = self.GetSelection()

        if not self.GetPyData(item)["has_expanded"]:
            self._extend(item)

def _expand_into(dest, src):
    vbox = wx.BoxSizer(wx.VERTICAL)
    vbox.Add(src, 1, wx.EXPAND | wx.ALL)
    dest.SetSizer(vbox)

class RegView(wx.Frame):
    def __init__(self, parent, registry):
        super(RegView, self).__init__(parent, -1, "Registry Viewer")

        vsplitter = wx.SplitterWindow(self, -1)
        panel_left = wx.Panel(vsplitter, -1)
        self._tree = RegistryTreeCtrl(panel_left, -1)
        _expand_into(panel_left, self._tree)

        hsplitter = wx.SplitterWindow(vsplitter, -1)
        panel_top = wx.Panel(hsplitter, -1)
        panel_bottom = wx.Panel(hsplitter, -1)

        self._value_list_view = ValuesListCtrl(panel_top, -1, style=wx.LC_REPORT)
        self._data_view = DataPanel(panel_bottom, -1)

        _expand_into(panel_top,    self._value_list_view)
        _expand_into(panel_bottom, self._data_view)

        hsplitter.SplitHorizontally(panel_top, panel_bottom)
        vsplitter.SplitVertically(panel_left, hsplitter)

        # give enough space in the data display for the hex output
        vsplitter.SetSashPosition(325, True)
        _expand_into(self, vsplitter)

        self._value_list_view.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnValueSelected)
        self._tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.OnKeySelected)

        self.SetSize((800, 600))
        self.Centre()

        self._tree.add_registry(registry)

    def OnKeySelected(self, event):
        item = event.GetItem()
        if not item.IsOk():
            item = self._tree.GetSelection()

        key = self._tree.GetPyData(item)["key"]

        self._data_view.clear_value()
        self._value_list_view.clear_values()
        for value in key.values():
            self._value_list_view.add_value(value)

    def OnValueSelected(self, event):
        item = event.GetItem()

        value = self._value_list_view.get_value(item.GetText())
        self._data_view.display_value(value)


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

