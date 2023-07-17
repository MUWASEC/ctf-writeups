from sympy import mod_inverse
from sympy import isprime
from secret import flag
from Crypto.Util.number import getPrime

e = 65537
while True:
    p = getPrime(1024)
    q = mod_inverse(e,p)
    if isprime(q):
        break

N=p*q

m=int(flag.encode("hex"),16)
c=pow(m,e,N)
f=open("pub.key","a")
f.write("e:" +str(e)+"\n")
f.write("N:" +str(N))
f.close()

f=open("flag.enc","w")
f.write(str(c))
f.close()
