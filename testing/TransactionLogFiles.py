#!/usr/bin/env python

from __future__ import print_function
import sys
from StringIO import StringIO
from Registry import Registry, RegistryLog

def print_test_testAAAA_testBBBB(reg):
    try:
        reg.root().find_key('testAAAA')
        print('testAAAA found!')
    except Exception:
        print('testAAAA not found!')

    try:
        reg.root().find_key('testBBBB')
        print('testBBBB found!')
    except Exception:
        print('testBBBB not found!')

def print_test_fdenytsconnections(reg):
    val = reg.root().find_key('ControlSet001\\Control\\Terminal Server').value('fDenyTSConnections').value()
    print('fDenyTSConnections = ' + str(val))

if len(sys.argv) != 4:
    print('You need to specify 3 files to test!')
    sys.exit(255)

primary_filepath = sys.argv[1]
log1_filepath = sys.argv[2]
log2_filepath = sys.argv[3]

primary = StringIO()
with open(primary_filepath, 'rb') as f:
    primary.write(f.read())

primary.seek(0)
log1 = RegistryLog.RegistryLog(primary, log1_filepath)
primary.seek(0)
log2 = RegistryLog.RegistryLog(primary, log2_filepath)
primary.seek(0)

reg = Registry.Registry(primary)

# Run the tests for the first time
print_test_testAAAA_testBBBB(reg)
print_test_fdenytsconnections(reg)

recover_header, recover_data = reg._regf.recovery_required()
if not (recover_header or recover_data):
    print('Recovery not required!')
    sys.exit(0)

print('Header recovery: ' + str(recover_header))
print('Data recovery: ' + str(recover_data))

apply_first = False
apply_second = False
logs_count = 0

if log1.is_eligible_log():
    logs_count += 1
    apply_first = True
if log2.is_eligible_log():
    logs_count += 1
    apply_second = True

print('Eligible log files count: ' + str(logs_count))

if logs_count == 1:
    if apply_first:
        print('Applying the first log')
        seqnum = log1.recover_hive()
    else:
        print('Applying the second log')
        seqnum = log2.recover_hive()
    print('Finishing with sequence number = ' + str(seqnum))
elif logs_count == 2:
    first_then_second = log1.is_starting_log(log2)
    if first_then_second:
        print('Applying the first log')
        seqnum = log1.recover_hive()
        print('Finishing with sequence number = ' + str(seqnum))
        print('Applying the second log')
        seqnum = log2.recover_hive_continue(seqnum + 1)
        print('Finishing with sequence number = ' + str(seqnum))
    else:
        print('Applying the second log')
        seqnum = log2.recover_hive()
        print('Finishing with sequence number = ' + str(seqnum))
        print('Applying the first log')
        seqnum = log1.recover_hive_continue(seqnum + 1)
        print('Finishing with sequence number = ' + str(seqnum))

primary.seek(0)
reg = Registry.Registry(primary)

# Run the tests again
print_test_testAAAA_testBBBB(reg)
print_test_fdenytsconnections(reg)