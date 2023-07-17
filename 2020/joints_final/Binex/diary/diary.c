#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<malloc.h>
#include<unistd.h>

struct diaryData
{
    int id;
    int day;
    int month;
    int year; 
    char data[160];
    struct diaryData *next;
};

int id=0;
struct diaryData *diary;

void init()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

int read_int()
{
    char c[16];
    read(0, c, 16);
    return atoi(c);
}

void read_str(int n, char* str)
{
    int c;
    c = read(0, str, n);
    str[c] = 0;
}

void add_diary()
{
    struct diaryData *d;
    struct diaryData *c;
    
    d = malloc(sizeof(struct diaryData));
    d->id = id++;
    printf("ID Diary : %d\n", d->id);
    printf("Day : ");
    d->day = read_int();
    printf("Month : ");
    d->month = read_int();
    printf("Year : ");
    d->year = read_int();
    puts("Data :");
    read_str(160, d->data);

    c = diary;
    if(c == NULL)
    {
        diary = d;
    }
    else
    {
        while(c->next != NULL)
        {
            c = c->next;
        }
        c->next = d;
    }
}

void delete_diary()
{
    int id;
    struct diaryData *c, *p = NULL;
    printf("ID : ");
    id = read_int();
    c = diary;

    while(c != NULL)
    {
        if(id == c->id)
        {
            break;
        }
        p = c;
        c = c->next;
    }
    if(c == NULL)
    {
        puts("Invalid ID");
    }
    else
    {
        if(p == NULL)
        {
            diary = c->next;
        }
        else
        {
            p->next = c->next;
        }
        free(c);
    }
}

void read_diary()
{
    struct diaryData *c = diary;
    int choice=1;

    while(c != NULL && choice == 1)
    {
        printf("ID   : %d\n", c->id);
        printf("Date : %02d-%02d-%04d\n", c->day, c->month, c->year);
        printf("%s\n\n", c->data);
        printf("[1] Next\n[2] Exit\n> ");
        choice = read_int();
        c = c->next;
    }
}

void edit_diary()
{
    int id;
    struct diaryData *c;
    printf("ID : ");
    id = read_int();
    c = diary;

    while(c != NULL)
    {
        if(id == c->id)
        {
            break;
        }
        c = c->next;
    }
    if(c == NULL)
    {
        puts("Invalid ID");
    }
    else
    {
        puts("Data :");
        read_str(160, c->data);
    }
}

void menu()
{
    puts("\n=== My Diary ===");
    puts("[1] Add Diary");
    puts("[2] Read Diary");
    puts("[3] Edit Diary");
    puts("[4] Delete Diary");
    puts("[5] Exit");
    printf("> ");
}

int main()
{
    int choice;
    init();
    while(1)
    {
        menu();
        choice = read_int();
        puts("");
        switch(choice)
        {
        case 1:
            add_diary();
            break;
        
        case 2:
            read_diary();
            break;
        
        case 3:
            edit_diary();
            break;
        
        case 4:
            delete_diary();
            break;
        
        case 5:
            return 0;
        
        default:
            puts("Invalid Choice");
        }
    }
}
