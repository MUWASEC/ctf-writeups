from pwn import *

elf = ELF('./election', checksec=False)
