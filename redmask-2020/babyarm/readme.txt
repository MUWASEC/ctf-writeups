nc 202.148.27.84 20002

Tambahan (15.54 WIB) tidak ada curl, nc, wget pada server

Author: circleous

# solution & problem

program berarsitektur arm, untuk bisa mendebug dan menjalankan program bisa menggunakan
device raspberry atau menggunakan virtual env seperti qemu.

terdapat 2 fungsi utama pada program, yaitu fungsi sym@sice dan sym@vuln. berikut
decompile dari fungsi sym@sice :
```
void sym.sice(void)
{
    int32_t iVar1;
    
    iVar1 = *(int32_t *)0x1045c + 0x1042e;
    sym.setvbuf((int16_t)**(undefined4 **)(iVar1 + *(int32_t *)0x10460), (char *)0x0, 2, 0);
    sym.setvbuf((int16_t)**(undefined4 **)(iVar1 + *(int32_t *)0x10464), (char *)0x0, 2, 0);
    sym.system("date +'%s'");
    return;
}
```

bisa dilihat diatas bahwa fungsi system mirip seperti pada arch x86.
decompile dari fungsi sym@vuln :
```
void sym.vuln(void)
{
    int16_t arg2;
    int16_t arg2_00;
    int16_t arg2_01;
    int16_t arg3;
    undefined auStack40 [32];
    
    arg3 = (int16_t)**(undefined4 **)(*(int32_t *)0x104a4 + 0x10478 + *(int32_t *)0x104a8);
    sym.fgets(auStack40, 0x1000, arg3);
    sym.__libc_close(0, arg2, arg3);
    sym.__libc_close(1, arg2_00, arg3);
    sym.__libc_close(2, arg2_01, arg3);
    return;
}
```

ada alokasi var stack dengan size 32 byte dan fungsi fgets yang membaca input hingga 4096 byte.
bug kali ini buffer overflow namun setelah fgets file descriptor 0, 1, 2 ditutup dengan fungsi
seperti "close();" pada bahasa c.

secara singkat, fd tersebut berfungsi :
fd 0 = stdin
fd 1 = stdout
fd 2 = stderr

jadi karna fd tadi diclose, kita tidak dapat memberikan input/output pada program. program 
dicompile secara static jadi kita dapat dengan mudah melakukan rop dengan gadget yang ada.

saya sempat membuat poc yg dapat membuka kembali fd 0 yg berfungsi sebagai input dan digunakan
untuk membaca file lokal lalu menaruhnya pada segment bss, namun tidak bisa membuka fd 1 yang
berfungsi sebagai output.

lalu langkah kedua saya ingat bahwa challenge ini mirip sekali dengan "ezrop revenge" di hacktoday 2019 
final dan dengan author yang sama pula. jadi problem fd yg diclose ini kita dapat menggunakan shellcode 
"socketcall system" dan dijadikan reverse shell, plus pada segment bss saat saya lihat di debugger memiliki 
flag rwxp yang berarti value pada segment itu dapat dieksekusi dengan shellcode.

jadi langkah eksploitasinya :
1.) rop untuk menulis value shellcode ke segment bss (seperti mov ptr ???, ??? pada x86)
2.) redirect eksekusi ke address bss
3.) buat listener, win

- referensi build env (qemu)
https://hydrasky.com/linux/create-debug-environment-for-arm-architecture-on-intel-processor/

- referensi exploitasi
https://reversingpwn.wordpress.com/2018/05/10/return-oriented-programming-di-arm/ (arm rop)
https://circleous.github.io/posts/hacktoday-2019-final-pwn/ (bypass close)