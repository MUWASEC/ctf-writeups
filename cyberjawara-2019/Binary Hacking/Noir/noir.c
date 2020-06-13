/*
 * Cyber Jawara 2019 - Noir
 *
 * gcc noir.c -o noir
 * socat TCP4-LISTEN:11338,reuseaddr,fork EXEC:"./noir" > /dev/null 2>&1 &
*/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int read_int(unsigned int len) {
  char input[len];
  fgets(input, len, stdin);
  return atoi(input);
}

void counting_sort() {
  unsigned int count[1001];
  int num;
  unsigned int i, j;

  for (i = 0; i < 1000; i++) {
    count[i] = 0;
  }

  num = read_int(5);
  while (num >= 0) {
    count[num]++;
    num = read_int(5);
  }

  printf("\nSorted:\n");
  for (i = 0; i < 1000; i++) {
    for (j = 0; j < count[i]; j++) {
      printf("%d\n", i);
    }
  }
  puts("");
}

void service() {
  printf("===~ WELCOME ~===\n");
  printf("Insert one number (0-1000) per line. To finish input, insert negative number.\n\n");
  counting_sort();
}

void hidden_shell() {
  execve("/bin/sh", 0, 0);
}

void init() {
  char buff[1];
  buff[0] = 0;
  setvbuf(stdout, buff, _IOFBF, 1);
  alarm(30);
}
 
int main() {
  init();
  service();
  return 0;
}