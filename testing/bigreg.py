import _winreg

hreg = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\willi")
print hreg

_winreg.SetValue(hreg, "big", _winreg.REG_SZ, "A" * 1024 * 20 )



