# desc
www 500

Author: Zafirr

You have a write what where, it should be easy to solve.
139.59.234.75 3005 

# hint
you will need some brute

# solution
in the program, all base address is given by reading /proc/self/maps content

problem :
- full protection binary
- arbitrary write, but only 1 time and then exit

using the given stack base address to calculate return address from the second call of __isoc99_scanf function
it should be around 1/4096 try to get the correct address because stack address aslr

step by step :
- brute force input by overwrite return address to main, if the program not crash/exit then we on the right track
- the second input we overwrite return address again with gets() because the rdi value pointing to stack address
- overflow stack address with gets(), then we redirect execution to system("/bin/sh")
