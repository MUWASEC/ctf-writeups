from pwn import *
import socket, struct

elf = ELF('./kudanil_lsi2', checksec=False)
#p = elf.process()
p = remote('not.codepwnda.id', 17009)
p.interactive()