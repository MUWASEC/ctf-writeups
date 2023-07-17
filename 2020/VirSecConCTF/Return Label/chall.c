#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

void vuln( void )
{
    char buffer[138];

    printf("Where should we send your package (printf is at %016llx)? \n\n", dlsym(RTLD_NEXT, "printf"));
    fflush(stdout);

    gets(buffer);

    puts(buffer);
    fflush(stdout);
}


int main(int argc, char** argv)
{

    vuln();

    return 0;
}
