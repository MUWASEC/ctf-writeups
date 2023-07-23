# desc
Printfail 1000

I managed to break pwntools with this.

By Jonathan (JBYoshi#5551 on discord)

nc puffer.utctf.live 4630

# solution
> from format string to arbitrary write
> overwrite return address on stack into one gadget address
