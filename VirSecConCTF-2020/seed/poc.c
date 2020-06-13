#include <time.h>
#include <stdlib.h>     /* srand, rand */
#include <stdio.h>

int main(){
  // int seed = ;
  srand(time(0));
  for (int i = 0 ; i <= 30 ; i++){
    int x;
    x = rand() & 0xF;
    printf("%d\n",x);
  }

  return 0;
}
