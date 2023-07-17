Are you ready for aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bin/shawhkj\xffwaa ?

Target: nc challs.xmas.htsp.ro 2001
Author: Th3R4nd0m


# solution
ada fungsi gets (overflow) yang diikuti pengecekan fungsi strstr dibeberapa address :
    0x00400826 = check string "sh"
    0x0040083e = check string "cat"

terdapat juga fungsi system di file soal + program tidak dicompile dengan PIE jadi kita dapat dengan mudah
menyusun payload ROP. jadi langkah eksplotasinya :
1.) overflow sampai return address
2.) redirect eksekusi ke fungsi gets dengan gadget $rdi berisi address bss
3.) input string "/bin/sh\x00"
4.) redirect eksekusi ke fungsi system dengan gadget $rdi berisi address bss (value bss sekarang /bin/sh)
5.) get shell