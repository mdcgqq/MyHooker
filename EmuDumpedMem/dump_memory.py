import lldb
import json
import hashlib
import zlib
import os
from datetime import datetime
from pathlib import Path
import sys


def dump_arch_info(target):
    triple = target.GetTriple()
    print(f'[dump_arch_info] triple => {triple}')
    arch, vendor, sys, abi = triple.split('-')
    if arch == 'aarch64' or arch == 'arm64':
        return 'arm64le'
    elif arch == 'aarch64_be':
        return 'arm64be'
    elif arch == 'armeb':
        return 'armbe'
    elif arch == 'arm':
        return 'armle'
    else:
        return ''

def dump_regs(frame):
    regs = {}
    registers = None
    for registers in frame.GetRegisters():
        for register in registers:
            register_name = register.GetName()
            register.SetFormat(lldb.eFormatHex)
            register_value = register.GetValue()
            if register_value is None:
                register_value = "N/A"  # 或者其他表示无法读取的值
                print(f"Can't read {register_name}")
            regs[register_name] = register_value
    print(f'regs => {json.dumps(regs, ensure_ascii=False, indent=4)}')
    return regs

def dump_memory_info(target):
    print('start dump_memory_info')
    sections = []
    for module in target.module_iter():
        for section in module.section_iter():
            module_name = module.file.GetFilename()
            start, end, size, name = get_section_info(target, section)
            section_info = {
                'module': module_name,
                'start': start,
                'end': end,
                'size': size,
                'name': name,
            }
            print(f'Appending: {name}')
            sections.append(section_info)
    return sections

def get_section_info(target, section):
    start_addr = section.GetLoadAddress(target)
    file_addr = section.GetFileAddress()
    size = section.GetByteSize()
    name = section.GetName()
    return start_addr, file_addr + start_addr, size, name

def _dump_memory(process, dump_path, black_list, max_seg_size):
    print('start dump memory')
    memory_list = []
    mem_info = lldb.SBMemoryRegionInfo()
    start_addr = -1
    next_region_addr = 0
    while next_region_addr > start_addr:
        err = process.GetMemoryRegionInfo(next_region_addr, mem_info)
        if not err.Success():
            print(f'GetMemoryRegionInfo failed, {err}, break')
            break
        next_region_addr = mem_info.GetRegionEnd()
        if next_region_addr >= sys.maxsize:
            print(f'next_region_addr:0x{next_region_addr:x} >= sys.maxsize, break')
            break
        start = mem_info.GetRegionBase()
        end = mem_info.GetRegionEnd()
        region_name = 'UNKNOWN'
        if mem_info.IsMapped():
            name = mem_info.GetName() if mem_info.GetName() else ''
            mem_info_obj = {
                'start': start,
                'end': end,
                'name': name,
                'permissions': {
                    'r': mem_info.IsReadable(),
                    'w': mem_info.IsWritable(),
                    'x': mem_info.IsExecutable(),
                },
                'content_file': '',
            }
            memory_list.append(mem_info_obj)
    for seg_info in memory_list:
        try:
            start_addr = seg_info['start']
            end_addr = seg_info['end']
            region_name = seg_info['name']
            permissions = seg_info['permissions']
            if not permissions['r']:
                print(f'Skip dump {region_name} permissions => {permissions}')
                continue
            predicted_size = end_addr - start_addr
            if predicted_size > max_seg_size:
                print(f'Skip dump {region_name} size:0x{predicted_size:x}')
                continue
            skip_dump = False
            for rule in black_list['startswith']:
                if region_name.startswith(rule):
                    skip_dump = True
                    print(f'Skip dump {region_name} hit startswith rule:{rule}')
            if skip_dump: continue
            for rule in black_list['endswith']:
                if region_name.endswith(rule):
                    skip_dump = True
                    print(f'Skip dump {region_name} hit endswith rule:{rule}')
            if skip_dump: continue
            for rule in black_list['includes']:
                if rule in region_name:
                    skip_dump = True
                    print(f'Skip dump {region_name} hit includes rule:{rule}')
            if skip_dump: continue
            ts = datetime.now()
            err = lldb.SBError()
            seg_content = process.ReadMemory(start_addr, predicted_size, err)
            tm = (datetime.now() - ts).total_seconds()
            if seg_content is None:
                print(f'Segment empty: @0x{start_addr:016x} {region_name} => {err}')
            else:
                print(f'Dumping @0x{start_addr:016x} {tm:.2f}s size:0x{len(seg_content):x}: {region_name} {permissions}')
                compressed_seg_content = zlib.compress(seg_content)
                md5_sum = hashlib.md5(compressed_seg_content).hexdigest() + '.bin'
                seg_info['content_file'] = md5_sum
                (dump_path / md5_sum).write_bytes(compressed_seg_content)
        except Exception as e:
            print(f'Exception reading segment {region_name}', exc_info=e)
    return memory_list

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -o -f dump_memory.dump_memory dump_memory')
    print("Memory dump command added successfully.")

def dump_memory(debugger, command, exe_ctx, result, internal_dict):
    print("Starting memory dump process...")
    target = exe_ctx.GetTarget()
    process = exe_ctx.GetProcess()
    
    arch_long = dump_arch_info(target)
    print(f"Architecture: {arch_long}")
    
    frame = process.GetSelectedThread().GetSelectedFrame()
    regs = dump_regs(frame)
    
    sections = dump_memory_info(target)
    
    dump_path = Path('your/dump/path')  # Set your dump path here
    black_list = {
        'startswith': ['/dev', '/system/fonts', '/dmabuf'],
        'endswith': ['(deleted)', '.apk', '.odex', '.vdex', '.dex', '.jar', '.art', '.oat', '.art]'],
        'includes': [],
    }
    max_seg_size = 64 * 1024 * 1024  # 64MB
    segments = _dump_memory(process, dump_path, black_list, max_seg_size)
    
    dump_info = {
        'architecture': arch_long,
        'registers': regs,
        'sections': sections,
        'segments': segments,
    }
    
    print("Saving memory dump to file...")
    try:
        with open(dump_path / 'memory_dump.json', 'w') as f:
            json.dump(dump_info, f, indent=4)
        print("Memory dump saved successfully.")
    except Exception as e:
        print(f"Failed to save memory dump: {e}")

    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)
    print("Memory dump process completed.")