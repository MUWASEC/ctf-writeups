from pwn import *
elf = ELF('./text_decorator', checksec=False)

def add_line(data, decor='n', color='r'):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b':\n', b'%s' % data)
    p.sendlineafter(b'?', decor.encode())
    if decor == 'y':
        p.sendlineafter(b': ', color.encode())



def remove_line():
    p.sendlineafter(b': ', b'3')

p = elf.process()
p.interactive()