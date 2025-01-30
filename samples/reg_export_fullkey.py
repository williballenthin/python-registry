#!/usr/bin/python

'''
Author: @tanhengyeow

Motivation for this script:
The current reg_export.py script exports the value of the registry key path and displays it to the console. This script extends it further by exporting out values of subkeys in a given registry key path and exports all the values it to a .reg file.

Pre-conditions:
+ Comment out "stdout.write(reg_format_header())" in ./reg_export.py before running this script.
'''

from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import os
import sys
import time
from Registry import Registry

def usage():
	#E.g of registry key path in text file: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
    return "  USAGE:\n\t%s <Windows Registry file> <Hive prefix> <Text File with Registry Key Path(s)> <Name of Output Folder>" % sys.argv[0]

#Function to display the windows registry header
def reg_format_header():
    """
    @rtype: byte string
    """
    return u"\ufeffWindows Registry Editor Version 5.00\r\n\r\n".encode("utf-16le")

#Function to collect all names from key(s)/subkey(s) from the given registry key
def rec(key, subNames,keyword,depth=0):	
	
	#Retrieve key path and obtain string after keyword
	regPath = str(key.path())	
	regPath = regPath.split(keyword)
	
	for i in range(len(regPath)):
		regPath[i] = str(regPath[i].replace("\\","\\\\"))

	#Store subkey(s) path into array
	if (depth != 0):
		subNames.append(regPath[i])

	for subkey in key.subkeys():
		rec(subkey, subNames, keyword, depth+1)

#Function to extract the registry keys
def reg_key_extract(regExport,regFile,regHive,regDest,regKeyCmd,regKeyParse):

	#Write windows registry header to dest .reg file
	f = open(regDest, 'w')
	f.write(reg_format_header())
	f.close() 

	subNames = []

	#Export main registry key	
	cmd = regExport + " " + regFile + " " + regHive + " " + regKeyCmd
	subprocess.Popen(cmd + " >> " + regDest, shell=True)
	
	time.sleep(0.05)
	
	#Traverse through registry key and collect all subkeys
	reg = Registry.Registry(regFile)
	key = reg.open(regKeyParse)
	
	#Retrieve keyword
	regPath = str(key.path())
	regKeyWord = regPath.rsplit("\\",1)
	length = len(regKeyWord)

	for i in range(length):
		regKeyWord[i] = str(regKeyWord[i])

	keyword = regKeyWord[length-1] + "\\"	

	#Recurse through subkey(s)
	rec(key,subNames,keyword)
  
	count = len(subNames)
	
	#For loop to export all subkeys from the main registry key into the dest .reg file
	for i in range(count):
		regSubKeyCmd = regKeyCmd + "\\\\" + subNames[i]
		cmd = regExport + " " + regFile + " " + regHive + " " + regSubKeyCmd
		subprocess.Popen(cmd + " >> " + regDest, shell=True)
		time.sleep(0.05)

def main(regFile,prefix,textFile,outputFolder):
	
	regExport = "./reg_export.py"
	
	#Check if destination folder exists
	try: 
   		os.makedirs(outputFolder)
	except OSError:
    		if not os.path.isdir(outputFolder):
        		raise	

	f = open(textFile)
	for regKeyParse in f.readlines():

		if (regKeyParse == '\n'):
			sys.exit(-1)		

		#Setting up the registry key parameters
		regKeyCmd = regKeyParse.replace("\\","\\\\") #Command line arguments require double backlash for registry key
		regKeyCmd = regKeyCmd.rstrip() # trim off trailing spaces
		regKeyParse = regKeyParse.rstrip()

		#To account for registry keys with spaces (e.g. Local Settings)	
		regKeyCmd = regKeyCmd.replace(" ","\ ")	
			
		#Obtain the name of the last parameter in the registry key path
		regKeyParm = regKeyParse.replace("\n","")
		regKeyParm = regKeyParm.rsplit("\\",1)
		length = len(regKeyParm)

		for i in range(length):
			regKeyParm[i] = str(regKeyParm[i])
		
		#Specify destination file to write to
		regDest = outputFolder + "/" + regKeyParm[length-1] + ".reg"
		regDest = str(regDest.replace("//","/"))
		regDest = regDest.replace(" ","\ ")

		reg_key_extract(regExport,regFile,prefix,regDest,regKeyCmd,regKeyParse)

	f.close()

if __name__ == "__main__":

    if len(sys.argv) < 5:
        print(usage())
        sys.exit(-1)

    main(*sys.argv[1:])
