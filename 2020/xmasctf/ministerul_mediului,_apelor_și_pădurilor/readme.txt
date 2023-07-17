I thought that mmap-ing memory is safer than using malloc, so safe that I don't even need to enforce security checks. Well, I got it very very wrong.

Confused about the title? Google is too: https://imgur.com/a/QsSt41g

Update: If you exploit was working locally, but not on the remote, now it should work. I fixed the reading.
Update: The flag is in /home/ctf/flag.txt (and for all other challenges)

Running on Ubuntu 20.04

Target: nc challs.xmas.htsp.ro 2003
Author: littlewho

# solution
arbitrary mmap tanpa fungsi munmap (fungsi untuk mendelete address mapping, mirip fungsi free)

full proteksi dan ada seccomp security seperti dibawah :
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0e 0xc000003e  if (A != ARCH_X86_64) goto 0016
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0b 0xffffffff  if (A != 0xffffffff) goto 0016
 0005: 0x15 0x09 0x00 0x00000000  if (A == read) goto 0015
 0006: 0x15 0x08 0x00 0x00000001  if (A == write) goto 0015
 0007: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0015
 0008: 0x15 0x06 0x00 0x00000003  if (A == close) goto 0015
 0009: 0x15 0x05 0x00 0x00000009  if (A == mmap) goto 0015
 0010: 0x15 0x04 0x00 0x0000000b  if (A == munmap) goto 0015
 0011: 0x15 0x03 0x00 0x0000000c  if (A == brk) goto 0015
 0012: 0x15 0x02 0x00 0x0000000f  if (A == rt_sigreturn) goto 0015
 0013: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0015
 0014: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x06 0x00 0x00 0x00000000  return KILL
```

jadi kita tidak bisa menggunakan syscall seperti execve, shellcode harus disusun hanya untuk membaca file
flag di /home/ctf/flag.txt dan juga sepertinya saat di re juga tidak ada bug seperti BoF.

karna menggunakan mmap, kita bisa menggunakan flags MAP_FIXED untuk mengoverwrite mapping libc lalu
mengoverwrite opcode/fungsi exit yang ada di libc dengan shellcode yang kita susun.

pada fungsi fcn.000018a0 ada seperti inisialisasi semacam logger namun filenya di hapus dengan fungsi unlink.
kita bisa menggunakan fd dari file logger tadi, itu dapat mempermudah kita untuk mengetahui letak address yang sudah kita mapping.

fungsi [1] = mmap
fungsi [2] = baca data di address mmap
fungsi [3] = tulis data di address mmap
fungsi [4] = exit

langkah eksplotasinya sebagai berikut :
1.) alokasi mmap dengan size besar, ini akan membuat region/page mmap kita berada sebelum region/page libc
2.) baca data di address mmap untuk mendapatkan address mmap kita dan kalkulasi base libc
3.) alokasi dengan flags MAP_FIXED, di manual mmap terterah "place the mapping at exactly that address" jadi yah ...
    flags tersebut berfungsi seperti overwrite region gitu
4.) overwrite data pada offset fungsi exit di libc dengan shellcode
5.) exit program dengan opsi "4", redirect ke shellcode, fun

side story :
ada perbedaan pas kalkulasi base libc di arch dan docker ubuntu 20.04, kalo di arch
libc base bisa didapat dengan menambah leak address mmap kita yang pertama dengan 0x21000. namun pada ubuntu 20.04 
sama seperti pada arch, namun harus ditambah dengan size dari region .tls sebesar 0x3000. pas di increase sizenya 
jadi 0x100000 dan ditambah size .tls sebesar 0x3000 maka leak base libc dapat dengan mudah didapat di arch atau ubuntu 20.04.

referensi :
- https://github.com/Naetw/CTF-pwn-tips#secret-of-a-mysterious-section---tls
- https://man7.org/linux/man-pages/man2/mmap.2.html