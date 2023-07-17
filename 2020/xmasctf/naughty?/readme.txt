You haven't been naughty, have you?

Target: nc challs.xmas.htsp.ro 2000
Author: Th3R4nd0m

# solution
alokasi $rsp sebesar 0x30.
fungsi fgets cuman nampung 0x47 byte (overflow) dan juga fungsi fgets akan otomatis menaruh '\x00' pada akhir inputan, jadi hanya 0x46 byte.

ada pengecekan pada address 0x004006b1, jika value $rbp-2 (atau byte ke 0x2e di $rsp) tidak sama dengan value 0xe4ff maka akan redirect eksekusi 
ke exit(0).

berarti 0x46 byte input - 0x38 byte rsp = 14 byte
jadi kita hanya bisa menulis rop sebesar 14 byte.

karna binary dicompile tanpa NX dan PIE + ada gadget jmp_rsp maka kita bisa redirect eksekusi ke shellcode di stack.
shellcode disini hanya bisa sebesar 6 byte (14 byte - 8 byte jmp_rsp). simple, kita hanya harus redirect eksekusi ke $rsp-0x40 dimana
itu adalah address yang berisi inputan kita. 

yang jadi masalah sekarang iyalah size shellcode (di padding pertama) tidak boleh lebih dari 0x2e, jika lebih maka akan mengoverwrite value
0xe4ff pada $rbp-2. kita bisa craft shellcode sendiri atau cara simplenya nyari di google (ada yg sizenya cuman 24 byte).

fun fact: 
0xe4ff jika di ubah ke menjadi shellcode maka akan menjadi 'jmp rsp', hint dari author mungkin ?