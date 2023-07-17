Just another pwnable...

nc 54.225.38.91 1027

Authors : KERRO && Anis_Boss

# Solution
just an integer overflow in the "write in file option"  that causes a buffer overflow ; leak offsets then ret2libc
