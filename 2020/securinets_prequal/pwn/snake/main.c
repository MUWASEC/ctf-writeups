#include <stdio.h>

void main()
{
setvbuf(stdout, NULL, _IONBF, 0);
//setreuid(geteuid(),geteuid());
setregid(getegid(),getegid());
system("/home/muwa00/n0w/snake/main.py");
}

