## Description
Just a start.

`nc chall.pwnable.tw 10000`

[start](https://pwnable.tw/static/chall/start)

## Solution
```js
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

karna NX tidak hidup, maka solutionnya kemungkinan memakai `shellcode`.  

leak address stack, input shellcode ulang dan return ke address stack  
yang tadi kita leak.  

[poc.py](./poc.py)