# Description
print the flag with shellcode < 20 bytes  

# Hint  
> use return address for defeat pie

# Solution
craft simple shellcode that mov ptr from `$rbp` then calculate the offset of `puts@got` and flag buffer on `bss`.  
after the calculation, mov address of flag to `$rdi` then call `puts@got` to print the flag