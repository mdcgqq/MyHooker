import lldb

def find_module(debugger:lldb.SBDebugger, command, result, internal_dict):
    lib_name = command
    target: lldb.SBTarget = debugger.GetSelectedTarget()
    for module in target.modules:
        stream = lldb.SBStream()
        module.GetDescription(stream)
        module_name = stream.GetData()
        if (lib_name in module_name):
            print("find " + module_name)
            for sec in module.section_iter():
                print(sec.GetName() + " -- " + hex(sec.GetLoadAddress(target)))

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -o -f lldb_find_module.find_module find_module')
