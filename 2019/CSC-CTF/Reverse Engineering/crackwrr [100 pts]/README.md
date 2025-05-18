# Description
Cracker jahat adalah h4ckwr baik yang tersakiti.....  
  
author: redspiracy

# Solution
`>` patch instruction at 0x000009a2 into `jne 0xa74`, this will bypass anti-ptrace.    
`>` or just patch the value at 0x0000094a from `mov dword [var_54h], 0x539` into `mov dword [var_54h], 0x3419`
```bash
[0x00000933]> s 0x0000094a
[0x0000094a]> wx c745ac193400
[0x0000094a]> pd1
│           0x0000094a      c745ac193400.  mov dword [var_54h], 0x3419

.....skip.....

╭─muwa00@ritalin ~/crackwrr [100 pts] ‹master*› 
╰─$ ./crackwrr.patch 
Hello Good Users!
==============
[+] Program running
[+] Version check...
[!] Version check disabled!
[!] Congrats! Flag: CCC{cr4ck3r_m0r3_p000w3rfull_Th4n_j0k33r}
```