#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

char *logName[8];
char *logContent[8];

void read_str(char *var, int n)
{
    int nn = read(0, var, n);
    var[nn-1] = 0;
}

int read_int()
{
    char val[5];
    read_str(val, 5);
    return atoi(val);
}

void create_log()
{
    FILE *f;
    char name[100];
    int inx;
    int sizeName;

    for(inx=0; inx<sizeof(logName); inx++)
    {
        if(logName[inx] == NULL)
        {
            break;
        }
    }
    if(inx == sizeof(logName))
    {
        puts("Log Full!");
    }
    else
    {
        printf("Insert name size (max 100) : ");
        sizeName = read_int();
        
        if(sizeName > 100 || sizeName <= 0)
        {
            puts("Invalid size");
        }
        else
        {
            logName[inx] = malloc(sizeName+5);

            printf("Insert log name : ");
            read_str(name, sizeName);
            sprintf(logName[inx], "./lg/%s", name);
            if(f = fopen(logName[inx], "r"))
            {
                fclose(f);
                puts("File already exist!");
                free(logName[inx]);
                logName[inx] = NULL;
            }
            else
            {
                f = fopen(logName[inx], "w");
                fclose(f);
                puts("Log created!");
            }
        }
    }
}

void write_log()
{
    int contentSize, inx;

    printf("Insert log index : ");
    inx = read_int();
    if(inx >= 0 && inx < 8)
    {
        if(logName[inx] == NULL)
        {
            puts("Empty Name!");
        }
        else
        {
            if(logContent[inx] != NULL)
            {
                free(logContent[inx]);
            }
            printf("Insert content size (max 500) : ");
            contentSize = read_int();
            if(contentSize>500 || contentSize<=0)
            {
                puts("Invalid size!");
            }
            else
            {
                puts("Insert content");
                logContent[inx] = malloc(contentSize);
                read_str(logContent[inx], contentSize);
            }
        }
    }
    else
    {
        puts("Invalid Index!");
    }
    
}

void save_log()
{
    FILE *f;
    int inx;

    printf("Insert log index : ");
    inx = read_int();
    if(inx >= 0 && inx < 8)
    {
        if(logName[inx] == NULL)
        {
            puts("Empty Name!");
        }
        else
        {
            if(logContent[inx] == NULL)
            {
                puts("Empty Content!");
            }
            else
            {
                f = fopen(logName[inx], "w");
                fprintf(f, "%s", logContent[inx]);
                fclose(f);
            }
        }
    }
    else
    {
        puts("Invalid Index!");
    }
    
}

void read_saved_log()
{
    FILE *f;
    int contentSize, inx;
    char ch;

    printf("Insert log index : ");
    inx = read_int();
    if(inx >= 0 && inx < 8)
    {
        if(logName[inx] == NULL)
        {
            puts("Empty Name!");
        }
        else
        {
            puts("Content :");
            f = fopen(logName[inx], "r");
            do
            {
                ch = fgetc(f);
                putchar(ch);
            }
            while(ch != EOF);
            fclose(f);
            puts("");
        }
    }
    else
    {
        puts("Invalid Index!");
    }
    
}

void delete_log()
{
    int inx;

    printf("Insert log index : ");
    inx = read_int();
    if(inx >= 0 && inx < 8)
    {
        if(logName[inx] == NULL)
        {
            puts("Empty Name!");
        }
        else
        {
            if(logContent[inx] != NULL)
            {
                free(logContent[inx]);
                logContent[inx] = NULL;
            }
            remove(logName[inx]);
            free(logName[inx]);
            logName[inx] = NULL;
        }
    }
    else
    {
        puts("Invalid Index!");
    }
    
}

void init()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

void menu()
{
    puts("\nMENU");
    puts("1. Create log");
    puts("2. (Over)Write log");
    puts("3. Save log");
    puts("4. Read saved log");
    puts("5. Delete log");
    puts("6. Exit");
    printf("> ");
}

int main()
{
    int c = 0;
    init();
    while(1)
    {
        menu();
        c = read_int();
        switch (c)
        {
        case 1:
            create_log();
            break;
        
        case 2:
            write_log();
            break;
        
        case 3:
            save_log();
            break;

        case 4:
            read_saved_log();
            break;

        case 5:
            delete_log();
            break;

        case 6:
            exit(0);
        
        default:
            puts("Invalid Choice");
        }
    }
}
