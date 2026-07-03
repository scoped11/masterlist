import idautils
import idaapi
import idc
import ida_funcs
import ida_bytes
import ida_name
import ida_segment

out = open(r"C:\Users\K\Desktop\PenisFinger\build\eac_ida_deep2.txt", "w")

def w(s):
    out.write(s + "\n")
    out.flush()
    print(s)

w("=" * 80)
w("EAC DRIVER DEEP ANALYSIS Part 2 (IDAPython)")
w("=" * 80)

# 1. Find API name strings via Strings iterator
w("\n=== API NAME STRINGS FOUND ===")
api_names = [
    "MmGetSystemRoutineAddress", "ObRegisterCallbacks",
    "PsSetCreateProcessNotifyRoutine", "PsSetLoadImageNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine", "ZwQuerySystemInformation",
    "NtQuerySystemInformation", "MmCopyVirtualMemory",
    "KeStackAttachProcess", "PsLookupProcessByProcessId",
    "IoCreateDevice", "IoCreateSymbolicLink", "RtlInitUnicodeString",
    "ExAllocatePool", "MmMapIoSpace", "ZwOpenKey", "ZwQueryValueKey",
    "PsGetCurrentProcess", "ZwQueryDirectoryFile", "MmGetPhysicalAddress",
    "ZwCreateFile", "NtReadVirtualMemory", "MmProbeAndLockPages",
    "KeAttachProcess", "ObOpenObjectByPointer", "NtClose",
    "PsGetProcessPeb", "PsGetProcessImageFileName",
    "IoGetCurrentProcess", "MmIsAddressValid",
    "ExAllocatePoolWithTag", "KeInitializeApc",
    "KeInsertQueueApc", "PsGetProcessWow64Process",
    "ZwOpenProcess", "ZwOpenThread",
    "FltRegisterFilter", "FltStartFiltering",
    "CmRegisterCallbackEx", "CmUnRegisterCallback",
    "ExRegisterCallback", "IoRegisterFsRegistrationChange",
    "PsRemoveCreateThreadNotifyRoutine",
    "PsRemoveLoadImageNotifyRoutine",
    "ObUnRegisterCallbacks",
]

found_apis = {}
for s in idautils.Strings():
    sval = idc.get_strlit_contents(s.ea, -1, s.strtype)
    if not sval:
        continue
    try:
        sval_str = sval.decode('utf-8', errors='replace')
    except:
        continue
    for api in api_names:
        if api in sval_str:
            if api not in found_apis:
                found_apis[api] = []
            found_apis[api].append(s.ea)

for api in api_names:
    if api in found_apis:
        addrs = found_apis[api]
        for addr in addrs[:2]:
            w("  FOUND: '%s' at 0x%X" % (api, addr))
            refs = list(idautils.XrefsTo(addr))
            for r in refs[:3]:
                w("    Referenced from 0x%X" % r.frm)
    else:
        w("  NOT FOUND: '%s'" % api)

# 2. VM entry stub analysis
w("\n=== VM ENTRY STUB (seg005: 0x14028D000-0x140290000) ===")
funcs = list(idautils.Functions())
stub_funcs = [f for f in funcs if f >= 0x14028D000 and f < 0x140290000]
w("Functions in stub: %d" % len(stub_funcs))
for f in stub_funcs:
    func = ida_funcs.get_func(f)
    size = func.size() if func else 0
    name = ida_name.get_name(f)
    w("  0x%X %s size=0x%X" % (f, name, size))
    head = f
    for i in range(min(15, size)):
        if head >= f + size:
            break
        disasm = idc.generate_disasm_line(head, 0)
        w("    0x%X: %s" % (head, disasm))
        head = idc.next_head(head, f + size)

# 3. .data function pointers
w("\n=== .DATA FUNCTION POINTERS ===")
data_start = 0x14020D000
ptr_count = 0
vm_ptrs = []
text_ptrs = []
for addr in range(data_start, data_start + 0x20000, 8):
    val = ida_bytes.get_qword(addr)
    if val >= 0x140001000 and val < 0x1425B3000:
        ptr_count += 1
        if val >= 0x140290000:
            vm_ptrs.append((addr, val))
        elif val < 0x14017F000:
            text_ptrs.append((addr, val))

w("Total code pointers in .data (first 128KB): %d" % ptr_count)
w("Pointers to .text: %d" % len(text_ptrs))
w("Pointers to VM section: %d" % len(vm_ptrs))
w("\nVM section pointers (dispatch table candidates):")
for addr, val in vm_ptrs[:40]:
    target_name = ida_name.get_name(val)
    w("  [0x%X] -> 0x%X (%s)" % (addr, val, target_name))

# 4. Decompile key functions
w("\n=== KEY FUNCTION DECOMPILATION ===")
try:
    import ida_hexrays
    if ida_hexrays.init_hexrays_plugin():
        key_addrs = [
            (0x14017E150, "DriverEntry"),
            (0x14017E17C, "sub_14017E17C_security_init"),
            (0x140089770, "sub_140089770_real_init"),
            (0x14017E190, "sub_14017E190_flt_caller"),
        ]

        for addr, label in key_addrs:
            func = ida_funcs.get_func(addr)
            if not func:
                w("\n--- %s (0x%X) --- [no function found]" % (label, addr))
                continue
            w("\n--- %s (0x%X) size=0x%X ---" % (label, addr, func.size()))
            try:
                cfunc = ida_hexrays.decompile(addr)
                if cfunc:
                    lines = str(cfunc).split('\n')
                    for line in lines[:80]:
                        w("  " + line)
                else:
                    w("  [decompilation failed]")
            except Exception as e:
                w("  [decompile error: %s]" % str(e))
    else:
        w("Hex-Rays not available")
except ImportError:
    w("ida_hexrays module not available")

# 5. Interesting strings in .rdata
w("\n=== INTERESTING STRINGS IN .RDATA ===")
rdata_start = 0x14017F020
rdata_end = 0x14020D000
keywords = ['driver', 'module', 'process', 'thread', 'callback',
           'hook', 'scan', 'detect', 'block', 'image', 'load',
           'register', 'device', 'filter', 'memory', 'query',
           'system', 'protect', 'check', 'hash', 'sign',
           'certif', 'trust', 'ioctl', 'dispatch', 'create',
           'ntdll', 'kernel', 'eac', 'anti', 'cheat',
           'object', 'handle', 'pid', 'crypt', 'virtual',
           'alloc', 'pool', 'mdl', 'pte', 'cr3', 'pml4',
           'minifilter', 'flt', 'irp', 'devobj', 'symlink',
           'mutex', 'event', 'section', 'mapping', 'notify',
           'debug', 'exception', 'trap', 'breakpoint',
           'stack', 'heap', 'guard', 'control', 'integrity',
           'game', 'overlay', 'inject', 'suspend', 'attach',
           'manual', 'map', 'unlink', 'hide', 'stealth',
           'report', 'telemetry', 'log', 'error', 'status',
           'client', 'server', 'connect', 'send', 'recv',
           'packet', 'encrypt', 'decrypt', 'encode', 'decode',
           'pipe', 'shared', 'token', 'privilege',
           'file', 'path', 'directory', 'enum']

for s in idautils.Strings():
    if s.ea >= rdata_start and s.ea < rdata_end:
        sval = idc.get_strlit_contents(s.ea, -1, s.strtype)
        if not sval:
            continue
        try:
            sval_str = sval.decode('utf-8', errors='replace')
        except:
            continue
        lower = sval_str.lower()
        if any(k in lower for k in keywords) and len(sval_str) > 4:
            w("  0x%X: \"%s\"" % (s.ea, sval_str[:150]))

# 6. VM section first function disassembly
w("\n=== VM SECTION FIRST 5 FUNCTIONS ===")
vm_start_funcs = [f for f in funcs if f >= 0x140290000]
vm_start_funcs.sort()
for f in vm_start_funcs[:5]:
    func = ida_funcs.get_func(f)
    size = func.size() if func else 0
    name = ida_name.get_name(f)
    w("  0x%X %s size=0x%X" % (f, name, size))
    head = f
    for i in range(min(20, size)):
        if head >= f + size:
            break
        disasm = idc.generate_disasm_line(head, 0)
        w("    0x%X: %s" % (head, disasm))
        head = idc.next_head(head, f + size)

out.close()
print("\n=== Part 2 analysis complete ===")
