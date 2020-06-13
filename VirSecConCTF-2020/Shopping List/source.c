#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

const char* logo = "  /$$$$$$  /$$                                     /$$                           /$$       /$$             /$$    \n\
 /$$__  $$| $$                                    |__/                          | $$      |__/            | $$    \n\
| $$  \\__/| $$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$ /$$$$$$$   /$$$$$$       | $$       /$$  /$$$$$$$ /$$$$$$  \n\
|  $$$$$$ | $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$| $$__  $$ /$$__  $$      | $$      | $$ /$$_____/|_  $$_/  \n\
 \\____  $$| $$  \\ $$| $$  \\ $$| $$  \\ $$| $$  \\ $$| $$| $$  \\ $$| $$  \\ $$      | $$      | $$|  $$$$$$   | $$    \n\
 /$$  \\ $$| $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$| $$  | $$| $$  | $$      | $$      | $$ \\____  $$  | $$ /$$\n\
|  $$$$$$/| $$  | $$|  $$$$$$/| $$$$$$$/| $$$$$$$/| $$| $$  | $$|  $$$$$$$      | $$$$$$$$| $$ /$$$$$$$/  |  $$$$/\n\
 \\______/ |__/  |__/ \\______/ | $$____/ | $$____/ |__/|__/  |__/ \\____  $$      |________/|__/|_______/    \\___/  \n\
                              | $$      | $$                     /$$  \\ $$                                        \n\
                              | $$      | $$                    |  $$$$$$/                                        \n\
                              |__/      |__/                     \\______/\n";

void print_menu( void )
{
    prin"1. Add Item\n2. List Items\n3. Edit Item\n4. Exit\n");
    fflush(stdout);
}

int read_int( void )
{
    char buffer[128];
    fgets(buffer, 128, stdin);
    return atoi(buffer);
}

int main(int argc, char** argv)
{
    char list[10][512];
    int next_item = 0;

    printf("%s\n", logo);
    print_menu();

    while( 1 )
    {
        printf("> ");
        fflush(stdout);
        int item = read_int();

        // Exit
        if( item == 4 ) break;

        switch(item)
        {
            case 1:
                printf("What would you like to add? ");
                fflush(stdout);
                fgets(list[next_item], 512, stdin);
                printf("Great, added: ");
                puts(list[next_item]);
                fflush(stdout);
                next_item = (next_item + 1) % 10;
                break;
            case 2:
                for(int i = 0; i < next_item; ++i){
                    printf("%i. %s\n", i+1, list[i]);
                }
                fflush(stdout);
                break;
            case 3:
                printf("Which item? ");
                fflush(stdout);
                item = read_int();
                if( item < 1 || item > next_item ){
                    printf("Invalid item\n");
                    fflush(stdout);
                } else {
                    printf("What's the new value? ");
                    fflush(stdout);
                    fgets(list[item], 512, stdin);
                    printf("New Value: ");
                    printf(list[item]);
                    printf("\n");
                    fflush(stdout);
                }
                break;
            default:
                printf("error: invalid choice\n");
                print_menu();
        }

    }

    return 0;
}
