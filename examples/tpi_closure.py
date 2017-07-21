#!/usr/bin/env python

import pdbparse
import sys
from optparse import OptionParser
from os.path import basename

lists = {
    #('_PEB', 'FlsListHead'): ,
    #('_RTL_CRITICAL_SECTION_DEBUG', 'ProcessLocksList'): ,
    #_KPROCESS -> _SINGLE_LIST_ENTRY; # SwapListEntry
    #_KTHREAD -> _SINGLE_LIST_ENTRY; # SwapListEntry
    ('_CM_KEY_BODY', 'KeyBodyList'): '_CM_KEY_BODY',
    ('_CM_KEY_CONTROL_BLOCK', 'FreeListEntry'): '_CM_KEY_CONTROL_BLOCK',
    ('_CM_KEY_CONTROL_BLOCK', 'KeyBodyListHead'): '_CM_KEY_BODY',
    ('_CM_KEY_SECURITY_CACHE', 'List'): '_CM_KEY_SECURITY_CACHE',
    ('_CM_NOTIFY_BLOCK', 'HiveList'): '_CM_NOTIFY_BLOCK',
    ('_CM_NOTIFY_BLOCK', 'PostList'): '_CM_POST_BLOCK',
    ('_CM_POST_BLOCK', 'CancelPostList'): '_CM_POST_BLOCK',
    ('_CM_POST_BLOCK', 'NotifyList'): '_CM_POST_BLOCK',
    ('_CM_POST_BLOCK', 'ThreadList'): '_CM_POST_BLOCK',
    ('_CM_POST_KEY_BODY', 'KeyBodyList'): '_CM_POST_KEY_BODY',
    ('_DISPATCHER_HEADER', 'WaitListHead'): '_KWAIT_BLOCK',
    ('_EJOB', 'JobLinks'): '_EPROCESS',
    ('_EJOB', 'JobSetLinks'): '_EJOB',
    ('_EJOB', 'ProcessListHead'): '_EPROCESS',
    ('_EPROCESS', 'ActiveProcessLinks'): '_EPROCESS',
    ('_EPROCESS', 'JobLinks'): '_EPROCESS',
    ('_EPROCESS', 'MmProcessLinks'): '_EPROCESS',
    ('_EPROCESS', 'SessionProcessLinks'): '_EPROCESS',
    ('_EPROCESS', 'ThreadListHead'): '_ETHREAD',
    ('_EPROCESS_QUOTA_BLOCK', 'QuotaList'): '_EPROCESS_QUOTA_BLOCK',
    ('_ERESOURCE', 'SystemResourcesList'): '_ERESOURCE',
    ('_ETHREAD', 'ActiveTimerListHead'): '_ETIMER',
    ('_ETHREAD', 'IrpList'): '_IRP',
    ('_ETHREAD', 'KeyedWaitChain'): '_ETHREAD',
    ('_ETHREAD', 'LpcReplyChain'): '_ETHREAD',
    ('_ETHREAD', 'PostBlockList'): '_CM_POST_BLOCK',
    ('_ETHREAD', 'ThreadListEntry'): '_ETHREAD',
    ('_ETIMER', 'ActiveTimerListEntry'): '_ETIMER',
    ('_ETIMER', 'WakeTimerListEntry'): '_ETIMER',
    ('_HANDLE_TABLE', 'HandleTableList'): '_HANDLE_TABLE',
    ('_IO_TIMER', 'TimerList'): '_IO_TIMER',
    ('_IRP', 'ThreadListEntry'): '_IRP',
    ('_KAPC', 'ApcListEntry'): '_KAPC',
    ('_KDEVICE_QUEUE', 'DeviceListHead'): '_KDEVICE_QUEUE_ENTRY',
    ('_KDPC', 'DpcListEntry'): '_KDPC',
    ('_KMUTANT', 'MutantListEntry'): '_KMUTANT',
    ('_KPROCESS', 'ProcessListEntry'): '_KPROCESS',
    ('_KPROCESS', 'ProfileListHead'): '_KPROFILE',
    ('_KPROCESS', 'ReadyListHead'): '_KTHREAD',
    ('_KPROCESS', 'ThreadListHead'): '_KTHREAD',
    ('_KPROFILE', 'ProfileListEntry'): '_KPROFILE',
    ('_KQUEUE', 'EntryListHead'): '_KQUEUE',
    ('_KQUEUE', 'ThreadListHead'): '_KTHREAD',
    ('_KTHREAD', 'MutantListHead'): '_KMUTANT',
    ('_KTHREAD', 'QueueListEntry'): '_KTHREAD',
    ('_KTHREAD', 'ThreadListEntry'): '_KTHREAD',
    ('_KTHREAD', 'WaitListEntry'): '_KTHREAD',
    ('_KTIMER', 'TimerListEntry'): '_KTIMER',
    ('_KWAIT_BLOCK', 'WaitListEntry'): '_KWAIT_BLOCK',
    ('_MMSUPPORT', 'WorkingSetExpansionLinks'): '_MMSUPPORT',
    ('_PEB_LDR_DATA', 'InInitializationOrderModuleList'): '_PEB_LDR_DATA',
    ('_PEB_LDR_DATA', 'InLoadOrderModuleList'): '_PEB_LDR_DATA',
    ('_PEB_LDR_DATA', 'InMemoryOrderModuleList'): '_PEB_LDR_DATA',
}

traversed = set()

def print_closure(s, nodes=False, comments=False):
    global structs
    global traversed
    traversed.add(s)
    
    if isinstance(s.fieldlist,str):
        return

    if nodes:
        print ('    %s_%d [label="{ %s | Index: %d \\n Size: %d \\n Members: %d }", shape=record];' % (s.name, s.tpi_idx,
            s.name, s.tpi_idx, s.size, s.count))

    for u in s.fieldlist.substructs:
        if u.leaf_type == "LF_MEMBER":
            if isinstance(u.index,str): continue
            if u.index.leaf_type == "LF_STRUCTURE":
                if u.index.name == '_LIST_ENTRY' and (s.name,u.name) in lists:
                    list_element_type = structs[lists[(s.name,u.name)]]
                    if nodes:
                        print ('    %s_%d -> %s_%d [style=dashed,color=forestgreen]; %s' % (s.name, s.tpi_idx, list_element_type.name, list_element_type.tpi_idx,
                                                                      "//" + u.name if comments else ""))
                    else:
                        print ('    %s -> %s [style=dashed,color=forestgreen]; %s' % (s.name, list_element_type.name,
                                                                   "//" + u.name if comments else ""))
                    next_type = list_element_type
                else:
                    if nodes:
                        print ('    %s_%d -> %s_%d [color=blue]; %s' % (s.name, s.tpi_idx, u.index.name, u.index.tpi_idx,
                                                          "//" + u.name if comments else ""))
                    else:
                        print ('    %s -> %s [color=blue]; %s' % (s.name, u.index.name,
                                                    "//" + u.name if comments else ""))
                    next_type = u.index

                if not next_type in traversed:
                    print_closure(next_type, nodes)
            elif (u.index.leaf_type == "LF_POINTER" and
                  not isinstance(u.index.utype,str) and
                  u.index.utype.leaf_type == "LF_STRUCTURE"):
                if nodes:
                    print ('    %s_%d -> %s_%d [style=dashed,color=red]; %s' % (s.name, s.tpi_idx, u.index.utype.name, u.index.utype.tpi_idx,
                                                                  "//" + u.name if comments else ""))
                else:
                    print ('    %s -> %s [style=dashed,color=red]; %s' % (s.name, u.index.utype.name,
                                                                  "//" + u.name if comments else ""))
                if not u.index.utype in traversed:
                    print_closure(u.index.utype, nodes)

parser = OptionParser()
parser.add_option("-n", "--nodes",
                  action="store_true", dest="nodes", default=False,
                  help="include detailed nodes in graph")
parser.add_option("-c", "--comments",
                  action="store_true", dest="comments", default=False,
                  help="append field names as comments")
(opts, args) = parser.parse_args()
if len(args) < 2:
    parser.error("Both PDB and base type name are required.")


pdb = pdbparse.parse(args[0])
structs = pdb.streams[2].structures
base_type = structs[args[1]]

print ("digraph %s {" % basename(args[0]).split('.')[0])
print_closure(base_type, opts.nodes, opts.comments)
print ("}")
