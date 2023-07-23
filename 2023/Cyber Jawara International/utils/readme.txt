# desc
utils 500

Author: Zafirr

easy kernel chall
139.59.234.75 3003 

# hint
the flag is in the module, you just need to read it, anyway possible

# solution
> double fetch race condition to bypass if check on dev_write
```if ((-1 < (int)*param_2) && ((int)*param_2 < 4))```
> then proceed to do out of bound read at index -232 for leaking flag content when program crashing
> beware that there's no function called on dev_write so race condition is a little bit harder (need to race 2 value)
> reference link :
https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/race/double-fetch/