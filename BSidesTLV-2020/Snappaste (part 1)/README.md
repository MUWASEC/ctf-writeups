# Description
We felt like there were not enough pasting services, so we created Snappaste! For better privacy, each pasted text can only be accessed once. We care about performance, and therefore we developed Snappaste in C++. We hope that we didn't introduce any security bugs :)

**URL:** [https://snappaste.ctf.bsidestlv.com/](https://snappaste.ctf.bsidestlv.com/)

**To compile, Use the following commands:** 
```c
gcc -c -std=c99 zlib/*.c  
g++ -c -std=c++14 snappaste.cc   
g++ -o snappaste *.o -pthread  
```

# Solution
vulnerable di program terdapat pada line 91 (sudah diberi komen) yaitu semacam integer overflow pada tipe data `dword`.  
saat melakukan beberapa tes/fuzzing, terdapat crash pada fungsi internal di glibc yaitu pada instruksi `mov qword ptr [rdi + rdx - 8], rcx`:
```c
──────────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────────────────────────────────────────────────────────
*RAX  0x7676767676767676 ('vvvvvvvv')
 RBX  0x5555555f9b40 (std::cout@@GLIBCXX_3.4) —▸ 0x7ffff7f83410 —▸ 0x7ffff7edb910 ◂— endbr64 
*RCX  0x4242424241414141 ('AAAABBBB')
 RDX  0x8
 RDI  0x7676767676767676 ('vvvvvvvv')
*RSI  0x4242424241414141 ('AAAABBBB')
 R8   0x7fffec003e70 —▸ 0x7ffff7a5b6f0 —▸ 0x7fffec001bb4 ◂— 0x3500000000
 R9   0x7fffec000080 —▸ 0x7fffec003e60 ◂— 0x0
*R10  0x5555555586a5 ◂— 0x73007970636d656d /* 'memcpy' */
*R11  0x7ffff7bcc4b0 (__memmove_avx_unaligned_erms) ◂— endbr64 
 R12  0x7ffff7a5bc60 —▸ 0x7ffff7a5bc70 ◂— 'HTTP/1.1'
 R13  0x7fffffffd83f ◂— 0x0
 R14  0x7fffffffd840 ◂— 0x0
 R15  0x7ffff7a5e700 ◂— 0x7ffff7a5e700
 RBP  0x7ffff7a5b820 —▸ 0x7ffff7a5b8a0 —▸ 0x7ffff7a5b8e0 —▸ 0x7ffff7a5b920 —▸ 0x7ffff7a5b960 ◂— ...
*RSP  0x7ffff7a5b7a8 —▸ 0x55555556e7f4 ◂— mov    rax, qword ptr [rbp - 0x68]
*RIP  0x7ffff7bcc53f (__memmove_avx_unaligned_erms+143) ◂— mov    qword ptr [rdi + rdx - 8], rcx

───────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x7ffff7bcc53f <__memmove_avx_unaligned_erms+143>    mov    qword ptr [rdi + rdx - 8], rcx
   0x7ffff7bcc544 <__memmove_avx_unaligned_erms+148>    mov    qword ptr [rdi], rsi
   0x7ffff7bcc547 <__memmove_avx_unaligned_erms+151>    ret    
 
   0x7ffff7bcc548 <__memmove_avx_unaligned_erms+152>    mov    ecx, dword ptr [rsi + rdx - 4]
   0x7ffff7bcc54c <__memmove_avx_unaligned_erms+156>    mov    esi, dword ptr [rsi]
   0x7ffff7bcc54e <__memmove_avx_unaligned_erms+158>    mov    dword ptr [rdi + rdx - 4], ecx
   0x7ffff7bcc552 <__memmove_avx_unaligned_erms+162>    mov    dword ptr [rdi], esi
   0x7ffff7bcc554 <__memmove_avx_unaligned_erms+164>    ret    
 
   0x7ffff7bcc555 <__memmove_avx_unaligned_erms+165>    movzx  ecx, word ptr [rsi + rdx - 2]
   0x7ffff7bcc55a <__memmove_avx_unaligned_erms+170>    movzx  esi, word ptr [rsi]
   0x7ffff7bcc55d <__memmove_avx_unaligned_erms+173>    mov    word ptr [rdi + rdx - 2], cx
────────────────────────────────────────────────────────────────────────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────────────────────────────────────────────────────────────────────────
In file: /usr/src/debug/glibc/sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S
   309 #endif
   310 L(between_8_15):
   311 	/* From 8 to 15.  No branch when size == 8.  */
   312 	movq	-8(%rsi,%rdx), %rcx
   313 	movq	(%rsi), %rsi
 ► 314 	movq	%rcx, -8(%rdi,%rdx)
   315 	movq	%rsi, (%rdi)
   316 	ret
   317 L(between_4_7):
   318 	/* From 4 to 7.  No branch when size == 4.  */
   319 	movl	-4(%rsi,%rdx), %ecx
```
`$rdx` bernilai 8 sehingga destinasi instruksi `mov` tertuju pada register `$rdi`. jadi crash terjadi akibat value di register `$rcx` dipindahkan
kedalam pointer yang terdapat pada register `$rdi` atau singkatnya nilai "AAAABBBB" di pindahkan ke pointer "vvvvvvvv". dari sini kita bisa  
membuat poc dimana kondisi `write-what-where` didapat saat kita mengkontrol value pada register `$rdi` dan `$rcx`.  
```
note :  
> value metadata => $rcx => what to write  
> value data     => $rdi => where to write
```
  
Jadi alur exploitasinya :  
- buat note biasa untuk mengambil `filepath`  
- ambil address `backdoor_filename` di-endpoint `/backdoor`  
- kirim payload 2 kali (16 char dibagi 2)  
- akses endpoint `/view/` untuk mendapatkan flag