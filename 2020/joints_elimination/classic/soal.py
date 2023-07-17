from string import printable
import random
from constants import flag,key

assert len(key)==15
prepare = ''.join(bin(ord(i))[2:].rjust(8,'0') for i in flag)

c = ''
for i in range(len(prepare)):
	c += chr(ord(prepare[i]) + ord(key[i%len(key)]) - ord('A'))

f = open('cipher','w')
f.write(c)
f.close()