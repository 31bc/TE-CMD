import sys, pefile, capstone
exe=sys.argv[1]
out=sys.argv[2]
try:
    pe=pefile.PE(exe)
    entry=pe.OPTIONAL_HEADER.AddressOfEntryPoint
    base=pe.OPTIONAL_HEADER.ImageBase
    # Find .text section
    text=None
    for sec in pe.sections:
        if b'.text' in sec.Name:
            text=sec
            break
    if not text:
        text=pe.sections[0]
    data=text.get_data()
    md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if pe.FILE_HEADER.Machine==0x8664 else capstone.CS_MODE_32)
    md.detail=True
    count=0
    with open(out,'w',encoding='utf-8',errors='ignore') as f:
        f.write(f"; EntryPoint: 0x{entry:X} ImageBase: 0x{base:X} .text va: 0x{text.VirtualAddress:X}\n")
        for insn in md.disasm(data[:8192], base+text.VirtualAddress):
            f.write(f"0x{insn.address:X}: {insn.mnemonic:8} {insn.op_str:20} ; {insn.bytes.hex()}\n")
            count+=1
            if count>500: break
        f.write(f"\n; Total {count} instructions disassembled\n")
    print(f"capstone: {count} insns")
except Exception as e:
    import traceback
    print(f"capstone fail: {e}")
    traceback.print_exc()
    open(out,'w').write(f"capstone error: {e}\n")
