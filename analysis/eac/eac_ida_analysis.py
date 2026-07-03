import idautils
import idaapi
import idc
import ida_funcs
import ida_bytes
import ida_name
import ida_xref
import ida_segment

out = open(r"C:\Users\K\Desktop\PenisFinger\build\eac_ida_deep.txt", "w")

def w(s):
    out.write(s + "\n")
    out.flush()
    print(s)

w("=" * 80)
w("EAC DRIVER DEEP ANALYSIS (IDAPython)")
w("=" * 80)

# 1. Segment info
w("\n=== SEGMENTS ===")
seg = ida_segment.get_first_seg()
while seg:
    name = ida_segment.get_segm_name(seg)
    w("  %s VA=0x%X-0x%X size=0x%X (%dKB) perm=%s%s%s" % (
        name.ljust(12), seg.start_ea, seg.end_ea, seg.size(), seg.size()//1024,
        'R' if seg.perm & 4 else '-',
        'W' if seg.perm & 2 else '-',
        'X' if seg.perm & 1 else '-'))
    seg = ida_segment.get_next_seg(seg.start_ea)

# 2. Function statistics
w("\n=== FUNCTION STATISTICS ===")
funcs = list(idautils.Functions())
w("Total functions: %d" % len(funcs))

text_funcs = []
vm_funcs = []
other_funcs = []
for f in funcs:
    func = ida_funcs.get_func(f)
    if not func:
        continue
    size = func.size()
    name = ida_name.get_name(f)
    if f < 0x14017F000:
        text_funcs.append((f, size, name))
    elif f >= 0x140290000:
        vm_funcs.append((f, size, name))
    else:
        other_funcs.append((f, size, name))

w("  .text functions: %d" % len(text_funcs))
w("  VM section functions: %d" % len(vm_funcs))
w("  Other functions: %d" % len(other_funcs))

# Top 20 largest functions
w("\n=== TOP 20 LARGEST FUNCTIONS ===")
all_f = text_funcs + vm_funcs + other_funcs
all_f.sort(key=lambda x: x[1], reverse=True)
for addr, size, name in all_f[:20]:
    seg = ida_segment.getseg(addr)
    segname = ida_segment.get_segm_name(seg) if seg else "?"
    w("  0x%X %-40s size=0x%X (%8d bytes) [%s]" % (addr, name, size, size, segname))

# 3. Cross-references FROM .text INTO VM section
w("\n=== CALLS FROM .TEXT INTO VM SECTION (0x140290000+) ===")
vm_calls = []
for f in text_funcs:
    addr = f[0]
    func = ida_funcs.get_func(addr)
    if not func:
        continue
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.CodeRefsFrom(head, 0):
            if xref >= 0x140290000:
                src_name = ida_name.get_name(addr)
                dst_name = ida_name.get_name(xref)
                vm_calls.append((head, xref, src_name, dst_name))
        for xref in idautils.CodeRefsFrom(head, 1):
            if xref >= 0x140290000:
                src_name = ida_name.get_name(addr)
                dst_name = ida_name.get_name(xref)
                vm_calls.append((head, xref, src_name, dst_name))

w("Total calls/jumps from .text to VM section: %d" % len(vm_calls))
for src, dst, sn, dn in vm_calls[:50]:
    w("  0x%X (%s) -> 0x%X (%s)" % (src, sn, dst, dn))

# 4. FltRegisterFilter xrefs
w("\n=== FltRegisterFilter CROSS-REFERENCES ===")
flt_addr = idc.get_name_ea_simple("FltRegisterFilter")
if flt_addr != idc.BADADDR:
    w("FltRegisterFilter IAT at: 0x%X" % flt_addr)
    for xref in idautils.XrefsTo(flt_addr):
        w("  Called from: 0x%X type=%d" % (xref.frm, xref.type))
        func = ida_funcs.get_func(xref.frm)
        if func:
            w("    In function: %s at 0x%X" % (ida_name.get_name(func.start_ea), func.start_ea))
else:
    w("FltRegisterFilter not found in names")

# 5. Look for dynamically resolved APIs using idc.find_binary
w("\n=== LOOKING FOR DYNAMIC API RESOLUTION PATTERNS ===")
api_names = [
    "MmGetSystemRoutineAddress",
    "ObRegisterCallbacks",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "ZwQuerySystemInformation",
    "NtQuerySystemInformation",
    "MmCopyVirtualMemory",
    "KeStackAttachProcess",
    "PsLookupProcessByProcessId",
    "IoCreateDevice",
    "IoCreateSymbolicLink",
    "RtlInitUnicodeString",
    "ExAllocatePool",
    "MmMapIoSpace",
    "ZwOpenKey",
    "ZwQueryValueKey",
    "PsGetCurrentProcess",
    "ZwQueryDirectoryFile",
    "MmGetPhysicalAddress",
    "ZwCreateFile",
    "ZwReadFile",
    "ZwWriteFile",
    "NtReadVirtualMemory",
    "MmProbeAndLockPages",
    "KeAttachProcess",
]

for api in api_names:
    # Use idc.find_binary with hex string
    hex_str = " ".join(["%02X" % ord(c) for c in api])
    addr = idc.find_binary(0x140001000, idc.SEARCH_DOWN, hex_str)
    if addr != idc.BADADDR and addr < 0x14028D000:
        w("  Found '%s' at 0x%X" % (api, addr))
        refs = list(idautils.XrefsTo(addr))
        for r in refs[:3]:
            w("    Referenced from 0x%X" % r.frm)
    else:
        w("  '%s' - NOT FOUND in .text/.rdata/.data" % api)

# 6. Look at the VM entry stub
w("\n=== VM ENTRY STUB ANALYSIS ===")
stub_funcs = [f for f in funcs if f >= 0x14028D000 and f < 0x140290000]
w("Functions in stub section (0x14028D000-0x140290000): %d" % len(stub_funcs))
for f in stub_funcs:
    func = ida_funcs.get_func(f)
    size = func.size() if func else 0
    name = ida_name.get_name(f)
    w("  0x%X %s size=0x%X" % (f, name, size))
    head = f
    for i in range(min(10, size // 2 + 1)):
        if head >= f + size:
            break
        disasm = idc.generate_disasm_line(head, 0)
        w("    %s" % disasm)
        head = idc.next_head(head, f + size)

# 7. Data section function pointer analysis
w("\n=== .DATA FUNCTION POINTERS ===")
data_start = 0x14020D000
data_end = 0x140284000
ptr_count = 0
vm_ptrs = []
text_ptrs = []
for addr in range(data_start, min(data_end, data_start + 0x20000), 8):
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
w("\nVM section pointers:")
for addr, val in vm_ptrs[:30]:
    target_name = ida_name.get_name(val)
    w("  [0x%X] -> 0x%X (%s)" % (addr, val, target_name))

# 8. Decompile key functions if Hex-Rays available
w("\n=== KEY FUNCTION DECOMPILATION ===")
try:
    import ida_hexrays
    if ida_hexrays.init_hexrays_plugin():
        # Decompile the FltRegisterFilter caller
        key_addrs = [
            (0x14017E150, "DriverEntry"),
            (0x14017E17C, "sub_14017E17C (security_init)"),
        ]
        # Add FltRegisterFilter caller
        if flt_addr != idc.BADADDR:
            for xref in idautils.XrefsTo(flt_addr):
                func = ida_funcs.get_func(xref.frm)
                if func:
                    key_addrs.append((func.start_ea, "FltRegisterFilter_caller"))
                    break

        for addr, label in key_addrs:
            w("\n--- %s (0x%X) ---" % (label, addr))
            try:
                cfunc = ida_hexrays.decompile(addr)
                if cfunc:
                    lines = str(cfunc).split('\n')
                    for line in lines[:60]:
                        w("  " + line)
                else:
                    w("  [decompilation failed]")
            except Exception as e:
                w("  [decompile error: %s]" % str(e))
    else:
        w("Hex-Rays not available")
except ImportError:
    w("ida_hexrays module not available")

# 9. Scan for VM dispatcher patterns in first few KB of VM section
w("\n=== VM SECTION ENTRY ANALYSIS (first 4KB) ===")
vm_start = 0x140290000
for addr in range(vm_start, min(vm_start + 0x1000, vm_start + 4096)):
    if idc.is_code(idc.get_full_flags(addr)):
        disasm = idc.generate_disasm_line(addr, 0)
        if disasm:
            w("  0x%X: %s" % (addr, disasm))

# 10. Search for interesting strings in .rdata
w("\n=== INTERESTING STRINGS IN .RDATA ===")
rdata_start = 0x14017F000
rdata_end = 0x14020D000
for s in idautils.Strings():
    if s.ea >= rdata_start and s.ea < rdata_end:
        sval = idc.get_strlit_contents(s.ea, -1, s.strtype)
        if sval:
            try:
                sval = sval.decode('utf-8', errors='replace')
            except:
                sval = str(sval)
            # Filter for interesting strings
            keywords = ['driver', 'module', 'process', 'thread', 'callback',
                       'hook', 'scan', 'detect', 'block', 'image', 'load',
                       'register', 'device', 'filter', 'memory', 'query',
                       'system', 'protect', 'check', 'hash', 'sign',
                       'certif', 'trust', 'ioctl', 'dispatch', 'create',
                       'ntdll', 'kernel', 'eac', 'anti', 'cheat',
                       'object', 'handle', 'pid', 'crypt', 'virtual',
                       'alloc', 'pool', 'mdl', 'pte', 'cr3', 'pml4',
                       'minifilter', 'flt', 'irp']
            lower = sval.lower()
            if any(k in lower for k in keywords) and len(sval) > 3:
                w("  0x%X: \"%s\"" % (s.ea, sval[:120]))

out.close()
print("\n=== Analysis complete. Results in eac_ida_deep.txt ===")
