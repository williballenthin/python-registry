#!/usr/bin/env python

# created by Glenn P. Edwards Jr.
#   http://hiddenillusion.blogspot.com
#       @hiddenillusion
# Version 0.1
# Date: 07-23-2013
# (while at FireEye)

from __future__ import print_function
from __future__ import unicode_literals

import os
import re
import sys
import time
try:
    from Registry import Registry
except ImportError:
    print("[!] Python-Registry not found")

"""
Some repetitively used functions
"""

def control_set_check(sys_reg): 
    """
    Determine which Control Set the system was using
    """
    registry = Registry.Registry(sys_reg)
    key = registry.open("Select")    
    for v in key.values():
        if v.name() == "Current":
            return v.value()             

def arch_check(sys_reg):
    """
    Architecture Check
    """    
    registry = Registry.Registry(sys_reg)
    key = registry.open("ControlSet00%s\\Control\\Session Manager\\Environment" % control_set_check(sys_reg)) 
    for v in key.values():
        if v.name() == "PROCESSOR_ARCHITECTURE":
            return v.value()                

def windir_check(sys_reg):
    """
    Locate the Windows directory
    """
    registry = Registry.Registry(sys_reg)    
    key = registry.open("ControlSet00%s\\Control\\Session Manager\\Environment" % control_set_check(sys_reg))    
    for v in key.values():
        if v.name() == "windir":
            return v.value()                

def os_check(soft_reg):
    """
    Determine the Operating System
    """
    registry = Registry.Registry(soft_reg)
    key = registry.open("Microsoft\\Windows NT\\CurrentVersion")
    for v in key.values():
        if v.name() == "ProductName":
            return v.value()                

def users_sids(soft_reg):
    '''
    Return a list of subkeys containing the users SIDs
    '''
    sid_list = []
    registry = Registry.Registry(soft_reg)
    key = registry.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    for v in key.subkeys():
        sid_list.append(v.name())

    return sid_list

def sid_to_user(sid_list, soft_reg):
    '''
    Return a list which maps SIDs to usernames
    '''
    # Grab the users profiles path based on the above SIDs
    mapping_list = []
    registry = Registry.Registry(soft_reg)
    for sid in sid_list:
        k = registry.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s" % sid)
        for v in k.values():
            if v.name() == "ProfileImagePath":
                mapping_list.append("{0:20} : {1}".format(v.value().rpartition('\\')[2],sid))

    return mapping_list
    
def users_paths(soft_reg, sid_list):
    '''
    Return a list of the profile paths for users on the system
    '''
    # Grab the users profiles path based on their SIDs
    users_paths_list = []
    registry = Registry.Registry(soft_reg)
    for sid in sid_list:
        k = registry.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s" % sid) 
        for v in k.values():
            if v.name() == "ProfileImagePath":
                users_paths_list.append(v.value())

    return users_paths_list   


def user_reg_locs(user_path_locs):
    """
    Returns the full path to each users NTUSER.DAT hive
    """
    user_ntuser_list = []
    for p in user_path_locs:
        if re.match('.*(Users|Documents and Settings).*', p):
            user_reg = os.path.join(p, "NTUSER.DAT")
            user_ntuser_list.append(user_reg)

    return user_ntuser_list

"""
Leverage the above functions and do something cool with them
"""
def env_settings(sys_reg):
    """
    Environment Settings
    """
    results = []
    sys_architecture = []
    registry = Registry.Registry(sys_reg)    
    print(("=" * 51) + "\n[+] Environment Settings\n" + ("=" * 51))
    key = registry.open("ControlSet00%s\\Control\\Session Manager\\Environment" % control_set_check(sys_reg))    
    for v in key.values():
        if v.name() == "PROCESSOR_ARCHITECTURE":
            sys_architecture = v.value()
            results.append("[-] Architecture.....: " + str(v.value()))            
        if v.name() == "NUMBER_OF_PROCESSORS":
            results.append("[-] Processors.......: " + str(v.value()))
        if v.name() == "TEMP":
            results.append("[-] Temp path........: " + str(v.value()))
        if v.name() == "TMP":
            results.append("[-] Tmp path.........: " + str(v.value()))                                                                             
    for line in results:
        print(line)

def tz_settings(sys_reg):
    """
    Time Zone Settings
    """
    results = []
    current_control_set = "ControlSet00%s" % control_set_check(sys_reg)
    k = "%s\\Control\\TimeZoneInformation" % current_control_set
    registry = Registry.Registry(sys_reg)
    key = registry.open(k)
    results.append(("=" * 51) + "\nTime Zone Settings\n" + ("=" * 51))    
    print("[-] Checking %s based on 'Select' settings" % current_control_set)
    results.append("[+] %s" % k)
    results.append("---------------------------------------")
    for v in key.values():
        if v.name() == "ActiveTimeBias":
            results.append("[-] ActiveTimeBias: %s" % v.value())
        if v.name() == "Bias":
            results.append("[-] Bias...: %s" % v.value())
        if v.name() == "TimeZoneKeyName":
            results.append("[-] Time Zone Name...: %s" % str(v.value()))

    return results

def os_settings(sys_reg, soft_reg):
    """
    Installed Operating System information
    """
    results = []
    registry = Registry.Registry(soft_reg)
    os_dict = {}
    key = registry.open("Microsoft\\Windows NT\\CurrentVersion")             
    for v in key.values():
        if v.name() == "ProductName":
            os_dict['ProductName'] = v.value()          
        if v.name() == "ProductId":
            os_dict['ProductId'] = v.value()              
        if v.name() == "CSDVersion":
            os_dict['CSDVersion'] = v.value()
        if v.name() == "PathName":
            os_dict['PathName'] = v.value()  
        if v.name() == "InstallDate":
            os_dict['InstallDate'] = time.strftime('%a %b %d %H:%M:%S %Y (UTC)', time.gmtime(v.value()))
        if v.name() == "RegisteredOrganization":
            os_dict['RegisteredOrganization'] = v.value()   
        if v.name() == "RegisteredOwner":
            os_dict['RegisteredOwner'] = v.value()          
                          
    print(("=" * 51) + "\n[+] Operating System Information\n" + ("=" * 51))
    print("[-] Product Name.....: %s" % os_dict['ProductName'])
    print("[-] Product ID.......: %s" % os_dict['ProductId'])
    print("[-] CSDVersion.......: %s" % os_dict['CSDVersion'])
    print("[-] Path Name........: %s" % os_dict['PathName']    )
    print("[-] Install Date.....: %s" % os_dict['InstallDate']       )
    print("[-] Registered Org...: %s" % os_dict['RegisteredOrganization'])
    print("[-] Registered Owner : %s" % os_dict['RegisteredOwner'])

def network_settings(sys_reg, soft_reg):
    """
    Network Settings
    """
    nic_names = []
    results_dict = {}
    nic_list = []
    nics_dict = {}
    int_list = []
    registry = Registry.Registry(soft_reg)
    key = registry.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
    print(("=" * 51) + "\n[+] Network Adapters\n" + ("=" * 51))

    # Populate the subkeys containing the NICs information
    for v in key.subkeys():
        nic_list.append(v.name())
  
    for nic in nic_list:
        k = registry.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%s" % nic)
        for v in k.values():
            if v.name() == "Description":
                desc = v.value()
                nic_names.append(desc)
            if v.name() == "ServiceName":
                guid = v.value()
        nics_dict['Description'] = desc
        nics_dict['ServiceName'] = guid

    reg = Registry.Registry(sys_reg)
    key2 = reg.open("ControlSet00%s\\services\\Tcpip\\Parameters\\Interfaces" % control_set_check(sys_reg))
    # Populate the subkeys containing the interfaces GUIDs
    for v in key2.subkeys():
        int_list.append(v.name())

    def guid_to_name(g):
        for k,v in nics_dict.items():
            '''
            k = ServiceName, Description
            v = GUID, Adapter name
            '''
            if v == g:
                return nics_dict['Description']

    # Grab the NICs info based on the above list
    for i in int_list:
        print("[-] Interface........: %s" % guid_to_name(i))
        print("[-] GUID.............: %s" % i)
        key3 = reg.open("ControlSet00%s\\services\\Tcpip\\Parameters\\Interfaces\\%s" % (control_set_check(sys_reg), i))  
        for v in key3.values():
            if v.name() == "Domain":
                results_dict['Domain'] = v.value()
            if v.name() == "IPAddress":
                # Sometimes the IP would end up in a list here so just doing a little check
                ip = v.value()
                results_dict['IPAddress'] = ip[0]                   
            if v.name() == "DhcpIPAddress":
                results_dict['DhcpIPAddress'] = v.value()                    
            if v.name() == "DhcpServer":
                results_dict['DhcpServer'] = v.value()                    
            if v.name() == "DhcpSubnetMask":
                results_dict['DhcpSubnetMask'] = v.value()      
   
        # Just to avoid key errors and continue to do because not all will have these fields 
        if not 'Domain' in results_dict: 
            results_dict['Domain'] = "N/A"
        if not 'IPAddress' in results_dict: 
            results_dict['IPAddress'] = "N/A"
        if not 'DhcpIPAddress' in results_dict: 
            results_dict['DhcpIPAddress'] = "N/A"                
        if not 'DhcpServer' in results_dict: 
            results_dict['DhcpServer'] = "N/A"        
        if not 'DhcpSubnetMask' in results_dict: 
            results_dict['DhcpSubnetMask'] = "N/A"        

        print("[-] Domain...........: %s" % results_dict['Domain'])
        print("[-] IP Address.......: %s" % results_dict['IPAddress'])
        print("[-] DHCP IP..........: %s" % results_dict['DhcpIPAddress'])
        print("[-] DHCP Server......: %s" % results_dict['DhcpServer'])
        print("[-] DHCP Subnet......: %s" % results_dict['DhcpSubnetMask'])
        print("\n"                                      )

def users_info(soft_reg):
    """
    Populating all of the user accounts
    ref: http://support.microsoft.com/kb/154599
    """     
    results = []
    results_dict = {}
    registry = Registry.Registry(soft_reg)
   
    results.append("{0:20} : {1}".format("Username", "SID"))
    results.append("---------------------------------------")    

    for l in sid_to_user(users_sids(soft_reg), soft_reg):
        results.append(l)
                            
    print(("=" * 51) + "\n[+] User Accounts\n" + ("=" * 51))
    for line in results:
        print(line)


if __name__ == "__main__":
    """
    Print out all of the information
    """            
    import sys
    sys_reg = sys.argv[1]
    soft_reg = sys.argv[2]
    print("[+] SYSTEM hive:   %s" % sys_reg)
    print("[+] SOFTWARE hive: %s" % soft_reg)
    print("[+] The system's Control Set is :",control_set_check(sys_reg))
    print("[+] The system's Architecture is:",arch_check(sys_reg))
    tz_settings(sys_reg)
    env_settings(sys_reg)
    os_settings(sys_reg, soft_reg)
    network_settings(sys_reg, soft_reg)
    users_info(soft_reg)
    user_reg_locs(users_paths(soft_reg, users_sids(soft_reg)))
