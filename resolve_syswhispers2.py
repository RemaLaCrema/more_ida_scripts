import idautils
import idaapi
import pefile

def hash(name):
    position = 0
    seed = 0x7d895397
    while name[position]:      
        seed ^= (((seed << 24) | (seed >> 8)) + (int.from_bytes(name[position:position+2], "little"))) & 0xffffffff
        position += 1
    return(seed)

def get_func_name(hashes, syscalls, hash_value):
    syscall = list(hashes.keys())[list(hashes.values()).index(hash_value)]
    return(syscalls[syscall])
  
SysCallsTableTmp = {}
SysCallsTable = {}
SysCallsTable_hashes = {}

pe = pefile.PE("C:\\Windows\\System32\\ntdll.dll")

for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    try:
        if b"Zw" in entry.name:
            SysCallsTableTmp[entry.name] = hex(pe.OPTIONAL_HEADER.ImageBase + entry.address)
    except:
        continue

SysCallsTable_sorted = sorted(SysCallsTableTmp.items(), key = lambda syscall: syscall[1])

for i in range(len(SysCallsTableTmp)):
    SysCallsTable[hex(i)] = SysCallsTable_sorted[i][0]
    SysCallsTable_hashes[hex(i)] = hash(SysCallsTable[hex(i)] + b"\x00")

xrefs = XrefsTo(0x4018F1)
for i in xrefs:
    ea = prev_head(i.frm)
    if "ecx" in generate_disasm_line(ea, 0):
        name = get_func_name(SysCallsTable_hashes, SysCallsTable, get_operand_value(ea, 1) & 0xffffffff)
        set_cmt(ea, name.decode("utf-8"), 1)
