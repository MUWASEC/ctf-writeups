# Description
Please submit flag with `CCC{...}` format.

author: avltree9798

# Solution
ida decompile  
```c
  v11[0] = objc_msgSend(v6, "initWithFormat:", CFSTR("%@TF"), CFSTR("C"));
  v7 = objc_alloc((Class)&OBJC_CLASS___NSMutableString);
  location = objc_msgSend(v7, "initWithFormat:", CFSTR("%@come_%@_%@-C"), CFSTR("W3l"), CFSTR("T0"), CFSTR("0bj3ct1v3"));
  objc_msgSend(flag, "appendFormat:", CFSTR("%@{%@}"), v11[0], location);
```
`FLAG: CTF{W3lcome_T0_0bj3ct1v3-C}`