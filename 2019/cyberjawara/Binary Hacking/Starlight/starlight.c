/*
 * Cyber Jawara 2019 - Starlight
 *
 * gcc starlight.c -o starlight
 * socat TCP4-LISTEN:11337,reuseaddr,fork EXEC:"./starlight" > /dev/null 2>&1 &
*/
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAXN 128

void show_flag() {
  FILE *fp;
  char password[MAXN];
  char input[MAXN];
  char flag[MAXN];

  fp = fopen("password.txt", "r");
  if (fp == NULL) {
    puts("Error: password not found");
    return;
  }

  printf("Pass: ");
  getchar();
  fgets(input, sizeof(input), stdin);
  strtok(input, "\n");

  fgets(password, sizeof(input), fp);
  strtok(password, "\n");

  if (strcmp(input, password) == 0) {
      fp = fopen("flag.txt", "r");
      if (fp == NULL) {
        puts("Error: flag not found");
        return;
      }
      fgets(flag, sizeof(flag), fp);
      puts(flag);
  }

}

void show_triangle() {
  int i = 0, j = 0;
  for (i = 0; i < 10; i++) {
    for (j = 0; j < 10 - (i + 1); j++) {
      printf(" ");
    }
    for (j = 0; j < (i + 1) * 2 - 1; j++) {
      printf("*");
    }
    puts("");
  }
  puts("");
}

void show_right_triangle() {
  int i = 0, j = 0;
  for (i = 0; i < 10; i++) {
    for (j = 0; j < (i + 1); j++) {
      printf("*");
    }
    puts("");
  }
  puts("");
}

void service() {
  FILE *fp;
  char path[MAXN];
  char lang[MAXN];
  char menu[MAXN];
  int choice;

  printf("Choose language (id/en/it): ");
  fgets(lang, sizeof(lang), stdin);
  strtok(lang, "\n");

  snprintf(path, MAXN, "languages/%s.lang", lang);

  fp = fopen(path, "r");

  if (fp == NULL) {
    puts("Error: language not found");
    return;
  }

  while (fgets(menu, sizeof(menu), fp)) {
    strtok(menu, "\n");
    printf("%s\n", menu);
  }
  fclose(fp);

  choice = (getchar() - '0');

  if (choice == 1) {
    show_triangle();
  } else if (choice == 2) {
    show_right_triangle();
  } else if (choice == 3) {
    show_flag();
  }
}

void init() {
  char buff[1];
  buff[0] = 0;
  setvbuf(stdout, buff, _IOFBF, 1);
  alarm(60);
}
 
int main() {
  init();
  service();
  return 0;
}